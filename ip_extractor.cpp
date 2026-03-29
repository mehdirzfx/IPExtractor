/*
 * Author : Mehdi Rezaei Far
 * IP:Port Extractor v2.0  -  Windows Optimized
 * - Streaming I/O (low RAM, works on 2GB+ files)
 * - Hand-written fast parsers (no std::regex bottleneck)
 * - Thread pool with lock-free per-thread buffers
 * - Windows native console colors
 *
 * Build (MinGW / MSYS2):
 *   g++ -O3 -std=c++17 -pthread -o ip_extractor.exe ip_extractor.cpp
 *
 * Build (MSVC):
 *   cl /O2 /std:c++17 /EHsc ip_extractor.cpp /Fe:ip_extractor.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <regex>

// ─────────────────────────────────────────────
//  Windows Console Colors
// ─────────────────────────────────────────────
static HANDLE g_hOut = INVALID_HANDLE_VALUE;
static HANDLE g_hErr = INVALID_HANDLE_VALUE;

static void setCol(HANDLE h, WORD a) {
    if (h != INVALID_HANDLE_VALUE) SetConsoleTextAttribute(h, a);
}

#define COL_RESET  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define COL_GREEN  (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_YELLOW (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_CYAN   (FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define COL_RED    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define COL_BOLD   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)

// ─────────────────────────────────────────────
//  Tunables
// ─────────────────────────────────────────────
static constexpr size_t READ_BUF   = 8  * 1024 * 1024;  // 8 MB read block
static constexpr size_t OUT_RSV    = 4  * 1024 * 1024;  // 4 MB per thread buffer

// ─────────────────────────────────────────────
//  Fast helpers (no alloc, no regex)
// ─────────────────────────────────────────────
static bool validIP(const char* s, int len) {
    if (len < 7 || len > 15) return false;
    int dots = 0, num = 0, dig = 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            num = num*10 + (c-'0');
            if (++dig > 3 || num > 255) return false;
        } else if (c == '.') {
            if (!dig) return false;
            dots++; num = 0; dig = 0;
        } else return false;
    }
    return dots == 3 && dig > 0;
}

// Read an IP starting at p, return byte length (0 = fail)
static int readIP(const char* p, const char* end) {
    const char* s = p; int dots = 0;
    while (p < end) {
        int num = 0, dig = 0;
        while (p < end && *p >= '0' && *p <= '9') { num = num*10+(*p-'0'); p++; dig++; }
        if (!dig || dig > 3 || num > 255) return 0;
        if (dots == 3) break;
        if (p >= end || *p != '.') return 0;
        p++; dots++;
    }
    return dots == 3 ? (int)(p - s) : 0;
}

// Read digits, return length read, store value in val
static int readDig(const char* p, const char* end, int& val) {
    int n = 0; val = 0;
    while (p+n < end && p[n] >= '0' && p[n] <= '9') { val = val*10+(p[n]-'0'); n++; }
    return n;
}

static const char* skipWS(const char* p, const char* end) {
    while (p < end && (*p==' '||*p=='\t')) p++;
    return p;
}

// Case-insensitive substring find (small needle)
static const char* findStr(const char* hay, int hlen, const char* needle, int nlen) {
    if (nlen > hlen) return nullptr;
    for (int i = 0; i <= hlen-nlen; i++)
        if (memcmp(hay+i, needle, nlen) == 0) return hay+i;
    return nullptr;
}

// ─────────────────────────────────────────────
//  Thread-local output buffer
// ─────────────────────────────────────────────
struct TResult {
    std::string buf;
    size_t      count = 0;

    void emit(const char* ip, int ipl, int port) {
        if (!validIP(ip, ipl) || port < 1 || port > 65535) return;
        buf.append(ip, ipl);
        buf += ':';
        // fast itoa
        char tmp[6]; int n = 0, p = port;
        char rev[6]; int r = 0;
        while (p) { rev[r++] = '0'+p%10; p /= 10; }
        for (int i = r-1; i >= 0; i--) tmp[n++] = rev[i];
        buf.append(tmp, n);
        buf += '\n';
        count++;
    }
    void emitS(const char* ip, int ipl, const char* portS, int portL) {
        int v = 0;
        for (int i = 0; i < portL; i++) {
            if (portS[i] < '0' || portS[i] > '9') return;
            v = v*10+(portS[i]-'0');
        }
        emit(ip, ipl, v);
    }
};

// ─────────────────────────────────────────────
//  Line iterator
// ─────────────────────────────────────────────
struct LineIt {
    const char* pos;
    const char* end;
    bool next(const char*& ls, int& ll) {
        if (pos >= end) return false;
        ls = pos;
        const char* nl = (const char*)memchr(pos, '\n', end-pos);
        if (nl) { ll = (int)(nl-pos); pos = nl+1; }
        else    { ll = (int)(end-pos); pos = end;  }
        if (ll > 0 && ls[ll-1] == '\r') ll--;
        return true;
    }
};

// ─────────────────────────────────────────────
//  Parser interface
// ─────────────────────────────────────────────
class IParser {
public:
    virtual ~IParser() = default;
    virtual void parse(const char* data, int len, TResult& out) = 0;
    virtual bool stateful() const { return false; }
};

// ─────────────────────────────────────────────
//  Generic parser — finds IP[:/ ,|]PORT anywhere
// ─────────────────────────────────────────────
class GenericParser : public IParser {
public:
    void parse(const char* data, int len, TResult& out) override {
        const char* p = data, *end = data+len;
        while (p < end) {
            int ipl = readIP(p, end);
            if (ipl > 0) {
                const char* q = p+ipl;
                if (q < end && (*q==':'||*q==' '||*q=='\t'||*q==','||*q=='|')) {
                    q++;
                    q = skipWS(q, end);
                    int v, n = readDig(q, end, v);
                    if (n > 0 && v >= 1 && v <= 65535) {
                        // ensure port not part of longer number
                        if (q+n >= end || !(q[n] >= '0' && q[n] <= '9'))
                            out.emit(p, ipl, v);
                    }
                }
                p += ipl; continue;
            }
            p++;
        }
    }
};

// ─────────────────────────────────────────────
//  Masscan parser
// ─────────────────────────────────────────────
class MasscanParser : public IParser {
public:
    void parse(const char* data, int len, TResult& out) override {
        LineIt it{data, data+len};
        const char* line; int ll;
        while (it.next(line, ll)) {
            if (!ll || line[0]=='#') continue;
            const char* e = line+ll;

            // "Discovered open port PORT/... on IP"
            const char* d = findStr(line, ll, "Discovered open port ", 21);
            if (d) {
                const char* p = d+21;
                int pv, pl = readDig(p, e, pv);
                if (pl) {
                    const char* on = findStr(p, (int)(e-p), " on ", 4);
                    if (on) {
                        const char* ips = on+4;
                        int ipl = readIP(ips, e);
                        if (ipl) out.emit(ips, ipl, pv);
                    }
                }
                continue;
            }
            // "open proto PORT IP"
            if (ll > 4 && memcmp(line,"open",4)==0) {
                const char* p = skipWS(line+4, e);
                while (p < e && *p!=' ' && *p!='\t') p++;  // skip proto
                p = skipWS(p, e);
                int pv, pl = readDig(p, e, pv);
                if (pl) {
                    p += pl; p = skipWS(p, e);
                    int ipl = readIP(p, e);
                    if (ipl) out.emit(p, ipl, pv);
                }
                continue;
            }
            // JSON {"ip":"...","ports":[{"port":80,...}]}
            if (line[0]=='{') {
                const char* ipp = findStr(line, ll, "\"ip\":\"", 6);
                const char* ptp = findStr(line, ll, "\"port\":", 7);
                if (ipp && ptp) {
                    const char* ips = ipp+6;
                    int ipl = 0;
                    while (ips+ipl < e && ips[ipl]!='"') ipl++;
                    const char* ps = skipWS(ptp+7, e);
                    int pv, pl = readDig(ps, e, pv);
                    if (ipl && pl) out.emit(ips, ipl, pv);
                }
            }
        }
    }
};

// ─────────────────────────────────────────────
//  Angry IP Scanner
// ─────────────────────────────────────────────
class AngryIPParser : public IParser {
public:
    void parse(const char* data, int len, TResult& out) override {
        LineIt it{data, data+len};
        const char* line; int ll;
        while (it.next(line, ll)) {
            if (!ll || line[0]=='#') continue;
            const char* e = line+ll;
            int ipl = readIP(line, e);
            if (!ipl) continue;
            const char* ip = line;
            const char* p  = line+ipl;
            // scan rest for port numbers
            while (p < e) {
                while (p < e && (*p < '0' || *p > '9')) p++;
                if (p >= e) break;
                int pv, pl = readDig(p, e, pv);
                if (pl && pv >= 1 && pv <= 65535) {
                    const char* q = p+pl;
                    bool ok = false;
                    if (q < e && *q == '/') {
                        // port/open or port/tcp or port/udp
                        ok = true;
                    } else if (q >= e || (*q != '.' && !(*q >= '0' && *q <= '9'))) {
                        ok = true;
                    }
                    if (ok) out.emit(ip, ipl, pv);
                }
                p += pl > 0 ? pl : 1;
            }
        }
    }
};

// ─────────────────────────────────────────────
//  Nmap Grepable (-oG)
// ─────────────────────────────────────────────
class NmapGrepParser : public IParser {
public:
    void parse(const char* data, int len, TResult& out) override {
        LineIt it{data, data+len};
        const char* line; int ll;
        while (it.next(line, ll)) {
            if (!ll || line[0]=='#') continue;
            if (ll < 5 || memcmp(line,"Host:",5)!=0) continue;
            const char* e  = line+ll;
            const char* p  = skipWS(line+5, e);
            int ipl = readIP(p, e);
            if (!ipl) continue;
            const char* ip = p;
            p += ipl;
            const char* pp = findStr(p, (int)(e-p), "Ports:", 6);
            if (!pp) continue;
            p = pp+6;
            while (p < e) {
                p = skipWS(p, e);
                int pv, pl = readDig(p, e, pv);
                if (!pl) { p++; continue; }
                p += pl;
                if (p < e && *p=='/') {
                    p++;
                    if (e-p >= 4 && memcmp(p,"open",4)==0) out.emit(ip, ipl, pv);
                }
                while (p < e && *p!=',') p++;
                if (p < e) p++;
            }
        }
    }
};

// ─────────────────────────────────────────────
//  Nmap Normal (-oN)  [STATEFUL]
// ─────────────────────────────────────────────
class NmapNormalParser : public IParser {
    char ip_[20] = {}; int ipl_ = 0;
public:
    bool stateful() const override { return true; }
    void parse(const char* data, int len, TResult& out) override {
        LineIt it{data, data+len};
        const char* line; int ll;
        while (it.next(line, ll)) {
            if (!ll) continue;
            const char* e = line+ll;
            if (ll > 21 && memcmp(line,"Nmap scan report for ",21)==0) {
                const char* p  = line+21;
                const char* lp = (const char*)memchr(p, '(', e-p);
                const char* is = lp ? lp+1 : p;
                int ipl = readIP(is, e);
                if (ipl) { memcpy(ip_, is, ipl); ipl_ = ipl; }
                continue;
            }
            if (!ipl_ || line[0] < '1' || line[0] > '9') continue;
            const char* p = line;
            int pv, pl = readDig(p, e, pv);
            if (!pl || pv < 1 || pv > 65535) continue;
            p += pl;
            if (p >= e || *p != '/') continue;
            p++;
            while (p < e && *p!=' '&&*p!='\t') p++;
            p = skipWS(p, e);
            if (e-p >= 4 && memcmp(p,"open",4)==0) out.emit(ip_, ipl_, pv);
        }
    }
};

// ─────────────────────────────────────────────
//  Nmap XML (-oX)  [STATEFUL]
// ─────────────────────────────────────────────
class NmapXMLParser : public IParser {
    char ip_[20] = {}; int ipl_ = 0; int port_ = 0;
public:
    bool stateful() const override { return true; }
    void parse(const char* data, int len, TResult& out) override {
        LineIt it{data, data+len};
        const char* line; int ll;
        while (it.next(line, ll)) {
            if (!ll) continue;
            const char* e = line+ll;

            const char* ap = findStr(line, ll, "addr=\"", 6);
            if (ap) {
                const char* is = ap+6; int ipl = 0;
                while (is+ipl < e && is[ipl]!='"') ipl++;
                if (validIP(is, ipl)) { memcpy(ip_, is, ipl); ipl_ = ipl; port_ = 0; }
            }
            const char* pp = findStr(line, ll, "portid=\"", 8);
            if (pp) {
                int v, n = readDig(pp+8, e, v);
                if (n) port_ = v;
            }
            const char* sp = findStr(line, ll, "state=\"", 7);
            if (sp) {
                const char* ss = sp+7;
                if (e-ss >= 4 && memcmp(ss,"open",4)==0)
                    if (ipl_ && port_ >= 1 && port_ <= 65535)
                        out.emit(ip_, ipl_, port_);
            }
        }
    }
};

// ─────────────────────────────────────────────
//  Custom Regex parser
//  User provides a regex with exactly 2 capture groups:
//    group 1 = IP,  group 2 = Port
//  OR 1 group containing "IP:Port" (split on last ':')
//  OR 0 groups — full match treated as "IP:Port"
//
//  Examples:
//   (\d+\.\d+\.\d+\.\d+):(\d+)          => classic IP:Port
//   host=(\d+\.\d+\.\d+\.\d+) port=(\d+) => key=value format
//   open\s+\w+\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)  => masscan-style (port first)
//
//  If groups are swapped (port in group1, IP in group2) the parser
//  auto-detects and swaps them.
// ─────────────────────────────────────────────
class CustomRegexParser : public IParser {
    std::regex  re_;
    int         grpIP_   = 1;   // which capture group holds IP
    int         grpPort_ = 2;   // which capture group holds Port
    int         numGroups_ = 0;
    bool        valid_   = false;

public:
    explicit CustomRegexParser(const std::string& pattern, bool swapGroups = false) {
        try {
            re_    = std::regex(pattern, std::regex::optimize);
            valid_ = true;
            // count groups by running on dummy string
            std::smatch m;
            std::string dummy = "";
            std::regex_search(dummy, m, re_);
            numGroups_ = (int)m.size() - 1; // size() includes group 0

            if (numGroups_ >= 2 && swapGroups) {
                grpIP_   = 2;
                grpPort_ = 1;
            } else if (numGroups_ == 1) {
                grpIP_   = 1;
                grpPort_ = 0; // will split on ':'
            } else if (numGroups_ == 0) {
                grpIP_   = 0; // full match, split on ':'
                grpPort_ = 0;
            }
        } catch (const std::regex_error& e) {
            fprintf(stderr, "\n  [Regex Error] %s\n", e.what());
            valid_ = false;
        }
    }

    bool isValid() const { return valid_; }

    void parse(const char* data, int len, TResult& out) override {
        if (!valid_) return;
        // std::regex works on std::string — we parse line by line to keep
        // memory bounded and avoid one giant string for an 8MB chunk
        LineIt it{data, data+len};
        const char* line; int ll;
        while (it.next(line, ll)) {
            if (!ll) continue;
            std::string s(line, ll);
            auto begin = std::sregex_iterator(s.begin(), s.end(), re_);
            auto end   = std::sregex_iterator();
            for (auto it2 = begin; it2 != end; ++it2) {
                auto& m = *it2;
                if (numGroups_ >= 2) {
                    // two groups: auto-detect which is IP
                    std::string g1 = m[grpIP_].str();
                    std::string g2 = m[grpPort_].str();
                    out.emitS(g1.data(), (int)g1.size(),
                              g2.data(), (int)g2.size());
                } else {
                    // one group or full match — split on last ':'
                    std::string full = (numGroups_ == 1) ? m[1].str() : m[0].str();
                    auto colon = full.rfind(':');
                    if (colon == std::string::npos) continue;
                    std::string ip   = full.substr(0, colon);
                    std::string port = full.substr(colon + 1);
                    out.emitS(ip.data(), (int)ip.size(),
                              port.data(), (int)port.size());
                }
            }
        }
    }
};

// ─────────────────────────────────────────────
//  Streaming extractor engine
// ─────────────────────────────────────────────
static size_t run(const std::string& inPath, const std::string& outPath,
                  IParser* parser, int numThreads) {

    HANDLE hIn = CreateFileA(inPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) {
        setCol(g_hErr, COL_RED);
        fprintf(stderr, "\n  [Error] Cannot open: %s\n", inPath.c_str());
        setCol(g_hErr, COL_RESET);
        return 0;
    }

    LARGE_INTEGER fsq; GetFileSizeEx(hIn, &fsq);
    size_t fileSize = (size_t)fsq.QuadPart;

    std::ofstream fout(outPath, std::ios::binary | std::ios::trunc);
    if (!fout) {
        setCol(g_hErr, COL_RED);
        fprintf(stderr, "\n  [Error] Cannot create: %s\n", outPath.c_str());
        setCol(g_hErr, COL_RESET);
        CloseHandle(hIn); return 0;
    }

    if (numThreads <= 0)
        numThreads = (int)std::thread::hardware_concurrency();
    if (numThreads <= 0) numThreads = 4;
    if (parser->stateful()) numThreads = 1;

    std::atomic<size_t> totalFound{0};
    std::atomic<size_t> totalRead{0};
    std::mutex          outMtx;
    auto                t0 = std::chrono::steady_clock::now();

    auto flushR = [&](TResult& r) {
        if (r.buf.empty()) return;
        std::lock_guard<std::mutex> lk(outMtx);
        fout.write(r.buf.data(), r.buf.size());
        totalFound += r.count;
        r.buf.clear(); r.count = 0;
    };

    // Progress thread
    std::atomic<bool> done{false};
    std::thread prog([&]{
        while (!done) {
            size_t rd = totalRead.load(), fd = totalFound.load();
            double pct = fileSize > 0 ? 100.0*rd/fileSize : 0;
            auto now = std::chrono::steady_clock::now();
            double sec = std::chrono::duration<double>(now-t0).count();
            double mbs = sec > 0.1 ? (rd/1048576.0/sec) : 0;
            int bw = 28, fill = (int)(bw*pct/100);
            std::string bar(fill,'='); if (fill<bw) bar+='>';
            bar += std::string(bw-(int)bar.size(),' ');
            setCol(g_hErr, COL_CYAN);
            fprintf(stderr,"\r  [%s]", bar.c_str());
            setCol(g_hErr, COL_RESET);
            fprintf(stderr," %5.1f%%", pct);
            setCol(g_hErr, COL_GREEN);
            fprintf(stderr," | %zu found", fd);
            setCol(g_hErr, COL_RESET);
            fprintf(stderr," | %.1f MB/s   ", mbs);
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        // Final
        size_t fd = totalFound.load();
        auto now = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(now-t0).count();
        double mbs = sec > 0.1 ? (fileSize/1048576.0/sec) : 0;
        setCol(g_hErr, COL_CYAN);
        fprintf(stderr,"\r  [============================]");
        setCol(g_hErr, COL_RESET);
        fprintf(stderr," 100.0%%");
        setCol(g_hErr, COL_GREEN);
        fprintf(stderr," | %zu found", fd);
        setCol(g_hErr, COL_RESET);
        fprintf(stderr," | %.1f MB/s   \n", mbs);
    });

    // Read loop (streaming, 8MB at a time)
    std::vector<char> rbuf(READ_BUF + 65536);
    std::vector<char> leftover; leftover.reserve(65536);

    while (true) {
        size_t loSz = leftover.size();
        if (loSz) memcpy(rbuf.data(), leftover.data(), loSz);
        leftover.clear();

        DWORD rd = 0;
        ReadFile(hIn, rbuf.data()+loSz, (DWORD)READ_BUF, &rd, nullptr);
        if (!rd) {
            if (loSz > 0) {
                TResult r; r.buf.reserve(OUT_RSV);
                parser->parse(rbuf.data(), (int)loSz, r);
                flushR(r); totalRead += loSz;
            }
            break;
        }

        size_t csz = loSz + rd;
        totalRead += rd;

        // Align to last newline
        size_t split = csz;
        for (size_t i = csz-1; i != (size_t)-1; i--)
            if (rbuf[i] == '\n') { split = i+1; break; }

        if (split < csz)
            leftover.assign(rbuf.data()+split, rbuf.data()+csz);

        size_t psz = split;
        if (!psz) continue;

        if (numThreads == 1) {
            TResult r; r.buf.reserve(OUT_RSV);
            parser->parse(rbuf.data(), (int)psz, r);
            flushR(r);
        } else {
            // Split among threads on newline boundaries
            std::vector<std::pair<size_t,size_t>> ranges;
            size_t per = psz / numThreads, off = 0;
            for (int t = 0; t < numThreads; t++) {
                size_t en = (t == numThreads-1) ? psz : off+per;
                if (en < psz) while (en < psz && rbuf[en]!='\n') en++;
                if (en < psz) en++;
                if (en > off) ranges.push_back({off, en-off});
                off = en; if (off >= psz) break;
            }
            const char* snap = rbuf.data();
            std::vector<TResult> results(ranges.size());
            std::vector<std::thread> threads; threads.reserve(ranges.size());
            for (size_t ti = 0; ti < ranges.size(); ti++)
                threads.emplace_back([&, ti]{
                    results[ti].buf.reserve(OUT_RSV);
                    parser->parse(snap+ranges[ti].first,(int)ranges[ti].second,results[ti]);
                });
            for (auto& th : threads) th.join();
            for (auto& r : results) flushR(r);
        }
    }

    done = true; prog.join();
    CloseHandle(hIn); fout.close();
    return totalFound.load();
}

// ─────────────────────────────────────────────
//  UI
// ─────────────────────────────────────────────
static std::string getIn(const char* prompt) {
    setCol(g_hOut, COL_BOLD); std::cout << prompt; setCol(g_hOut, COL_RESET);
    std::string s; std::getline(std::cin, s);
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, s.find_last_not_of(" \t\r\n")-a+1);
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hErr = GetStdHandle(STD_ERROR_HANDLE);
    DWORD mode; if (GetConsoleMode(g_hOut,&mode))
        SetConsoleMode(g_hOut, mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    setCol(g_hOut, COL_CYAN);
    std::cout <<
        "\n"
        "  +=========================================+\n"
        "  |        IP:Port Extractor  v1.0          |\n"
        "  |   Streaming | Multi-Thread | Windows    |\n"
		"  |          Developed By s3nat0r           |\n"
        "  +=========================================+\n\n";
    setCol(g_hOut, COL_RESET);

    while (true) {
        setCol(g_hOut, COL_BOLD);
        std::cout << "  Select Format:\n"; setCol(g_hOut, COL_RESET);

        auto item = [](const char* n, const char* d) {
            setCol(g_hOut, COL_YELLOW); std::cout << "    " << n;
            setCol(g_hOut, COL_RESET);  std::cout << "  " << d << "\n";
        };
        item("1", "Angry IP Scanner   (.txt / .csv)");
        item("2", "Masscan            (.txt / .json)");
        item("3", "Nmap Normal        (-oN)  [single-thread]");
        item("4", "Nmap Grepable      (-oG)");
        item("5", "Nmap XML           (-oX)  [single-thread]");
        item("6", "Generic / Auto     (any IP:Port format)");
        item("7", "Custom Regex       (define your own pattern)");
        item("0", "Exit");
        std::cout << "\n";

        std::string ch = getIn("  Choice: ");
        int choice = 0;
        try { choice = std::stoi(ch); } catch (...) {}
        if (choice == 0) { setCol(g_hOut,COL_GREEN); std::cout<<"\n  Bye!\n\n"; setCol(g_hOut,COL_RESET); break; }
        if (choice < 1 || choice > 7) { setCol(g_hOut,COL_RED); std::cout<<"  Invalid.\n\n"; setCol(g_hOut,COL_RESET); continue; }

        std::string inp = getIn("  Input  file : ");
        std::string out = getIn("  Output file : ");
        if (inp.empty()||out.empty()) { setCol(g_hOut,COL_RED); std::cout<<"  Paths empty.\n\n"; setCol(g_hOut,COL_RESET); continue; }

        std::string ths = getIn("  Threads (0=auto) : ");
        int nth = 0; try { nth = std::stoi(ths); } catch (...) {}

        IParser* p = nullptr; const char* fn = "";
        switch (choice) {
            case 1: p = new AngryIPParser();    fn = "Angry IP Scanner"; break;
            case 2: p = new MasscanParser();    fn = "Masscan";          break;
            case 3: p = new NmapNormalParser(); fn = "Nmap Normal";      break;
            case 4: p = new NmapGrepParser();   fn = "Nmap Grepable";    break;
            case 5: p = new NmapXMLParser();    fn = "Nmap XML";         break;
            case 6: p = new GenericParser();    fn = "Generic/Auto";     break;
            case 7: {
                fn = "Custom Regex";
                std::cout << "\n";
                setCol(g_hOut, COL_CYAN);
                std::cout <<
                    "  Regex format guide:\n"
                    "    - Use 2 capture groups: group1=IP, group2=Port\n"
                    "    - OR 1 group containing IP:Port (split on last ':')\n"
                    "    - OR 0 groups: full match treated as IP:Port\n"
                    "\n"
                    "  Examples:\n";
                setCol(g_hOut, COL_YELLOW);
                std::cout <<
                    "    (\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)\n"
                    "    host=(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+port=(\\d+)\n"
                    "    open\\s+\\w+\\s+(\\d+)\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)  <- port,IP order\n";
                setCol(g_hOut, COL_RESET);
                std::cout << "\n";

                std::string pat = getIn("  Regex pattern : ");
                if (pat.empty()) {
                    setCol(g_hOut, COL_RED);
                    std::cout << "  Pattern empty.\n\n";
                    setCol(g_hOut, COL_RESET);
                    continue;
                }

                // Ask if groups are swapped (port=group1, ip=group2)
                std::string swapAns = getIn("  Is group1=Port and group2=IP? (y/N) : ");
                bool swapGroups = (!swapAns.empty() &&
                                   (swapAns[0]=='y' || swapAns[0]=='Y'));

                auto* crp = new CustomRegexParser(pat, swapGroups);
                if (!crp->isValid()) {
                    delete crp;
                    std::cout << "\n";
                    continue;
                }
                p = crp;

                // Show parsed config
                setCol(g_hOut, COL_CYAN);
                std::cout << "  Pattern : " << pat << "\n";
                if (swapGroups) std::cout << "  Groups  : group1=Port, group2=IP\n";
                else            std::cout << "  Groups  : group1=IP,   group2=Port\n";
                setCol(g_hOut, COL_RESET);
                break;
            }
        }

        if (!p) continue;

        int eff = nth <= 0 ? (int)std::thread::hardware_concurrency() : nth;
        if (p->stateful()) eff = 1;

        std::cout << "\n";
        setCol(g_hOut,COL_BOLD); std::cout << "  Format  : "; setCol(g_hOut,COL_CYAN);  std::cout << fn << "\n"; setCol(g_hOut,COL_RESET);
        setCol(g_hOut,COL_BOLD); std::cout << "  Input   : "; setCol(g_hOut,COL_RESET); std::cout << inp << "\n";
        setCol(g_hOut,COL_BOLD); std::cout << "  Output  : "; setCol(g_hOut,COL_RESET); std::cout << out << "\n";
        setCol(g_hOut,COL_BOLD); std::cout << "  Threads : "; setCol(g_hOut,COL_RESET); std::cout << eff;
        if (p->stateful()) std::cout << " (stateful - forced single-thread)";
        std::cout << "\n\n";

        auto t0  = std::chrono::steady_clock::now();
        size_t cnt = run(inp, out, p, nth);
        auto t1  = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(t1-t0).count();
        delete p;

        std::cout << "\n";
        setCol(g_hOut,COL_GREEN); setCol(g_hOut,COL_BOLD); std::cout << "  Done!\n"; setCol(g_hOut,COL_RESET);
        setCol(g_hOut,COL_BOLD);  std::cout << "  Found   : "; setCol(g_hOut,COL_GREEN); std::cout << cnt; setCol(g_hOut,COL_RESET); std::cout << " IP:Port pairs\n";
        setCol(g_hOut,COL_BOLD);  std::cout << "  Time    : "; setCol(g_hOut,COL_RESET);
        if (sec < 1.0) std::cout << (int)(sec*1000) << " ms\n";
        else           printf("%.2f s\n", sec);
        std::cout << "\n";
    }
    return 0;
}
