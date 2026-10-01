# Lean sandbox image — crypto / forensics / rev / misc only, fast to build.
# ponytail: skip the heavy go/cargo/playwright/angr layers of Dockerfile.agent
# until a batch shows we need them. This is enough for a first InterCode number
# (crypto+forensics+rev+general-skills = ~94 of the 100 tasks).
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev build-essential git curl wget jq file \
    binutils gdb radare2 \
    exiftool binwalk foremost p7zip-full poppler-utils tshark steghide \
    hashcat john ruby ruby-dev \
    fcrackzip pdfcrack wordlists \
    libgmp-dev libmpfr-dev libmpc-dev libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# rockyou wordlist for hash/archive/steg cracking (john, hashcat, fcrackzip,
# stegseek). Kali ships it gzipped; unpack once and expose at a stable path.
RUN gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
ENV WORDLIST=/usr/share/wordlists/rockyou.txt

RUN pip3 install --break-system-packages \
    pycryptodome sympy z3-solver factordb-python xortool requests
# ponytail: pwntools/unicorn (needs cmake) deferred to Dockerfile.agent — not
# needed for crypto/forensics/static-rev.
RUN gem install zsteg || true   # PNG/BMP steg (non-critical)

WORKDIR /work
