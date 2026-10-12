"""검증용 원문 가져오기 — URL을 curl로 받아 제목·게시일 후보·본문 텍스트를 출력한다.

사용: python3 integrated/scripts/fetch_page.py URL [--grep 키워드 ...] [--max 4000]
  --grep: 본문에서 키워드가 든 문장만 앞뒤로 보여줌(대소문자 무시)
웹페치 도구가 이 환경에서 DNS 실패하므로 curl(프록시 경유)을 쓴다. 일부 사이트는 브라우저 UA가 필요하다.
"""
import argparse
import html
import re
import subprocess
import sys

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
DATE_PATS = [
    r'"datePublished"\s*:\s*"([^"]+)"', r'article:published_time"\s+content="([^"]+)"', r'content="([^"]+)"\s+property="article:published_time"',
    r'name="(?:pubdate|publish-date|date)"\s+content="([^"]+)"', r'<time[^>]*datetime="([^"]+)"', r'"dateModified"\s*:\s*"([^"]+)"',
]


def fetch(url):
    p = subprocess.run(["curl", "-sS", "-L", "-m", "30", "-A", UA, "-H", "Accept-Language: ko,en;q=0.8", "-w", "\n__HTTP__%{http_code}", url],
                       capture_output=True)
    raw = p.stdout.decode("utf-8", errors="ignore")
    code = raw.rsplit("__HTTP__", 1)[-1].strip() if "__HTTP__" in raw else "000"
    body = raw.rsplit("\n__HTTP__", 1)[0]
    if "charset=euc-kr" in body[:3000].lower():
        body = p.stdout.decode("euc-kr", errors="ignore").rsplit("\n__HTTP__", 1)[0]
    return code, body, p.stderr.decode(errors="ignore").strip()


def to_text(h):
    h = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer|header|form)[^>]*>.*?</\1>", " ", h)
    h = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</h\d>|</li>|</tr>", "\n", h)
    t = html.unescape(re.sub(r"<[^>]+>", " ", h))
    lines = [re.sub(r"[ \t ]+", " ", l).strip() for l in t.split("\n")]
    return "\n".join(l for l in lines if len(l) > 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--grep", nargs="*", default=[])
    ap.add_argument("--max", type=int, default=4000)
    a = ap.parse_args()
    code, body, err = fetch(a.url)
    print(f"HTTP {code}" + (f" · {err}" if err else ""))
    if not body.strip():
        sys.exit(0)
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    print("제목:", html.unescape(m.group(1)).strip()[:200] if m else "-")
    dates = []
    for pat in DATE_PATS:
        dates += re.findall(pat, body[:300000])
    print("게시일 후보:", ", ".join(dict.fromkeys(d[:25] for d in dates)) or "-")
    text = to_text(body)
    if a.grep:
        kws = [k.lower() for k in a.grep]
        sents = re.split(r"(?<=[.!?。다])\s+|\n", text)
        hits = [s for s in sents if any(k in s.lower() for k in kws)]
        print(f"--- 키워드 문장 {len(hits)}개")
        out = "\n".join(dict.fromkeys(h.strip() for h in hits if h.strip()))
        print(out[: a.max])
    else:
        print("--- 본문")
        print(text[: a.max])


if __name__ == "__main__":
    main()
