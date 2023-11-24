# CMU-HTTP

This repository contains the starter code for ***CMU 15-441/641 Networking and the Internet Project 3: CMU-HTTP***.

## 1. Files
- `Makefile`: Contains rules for `make`.
- `README.md`: Current document.
- `cp1`: CP1 scripts and examples.
- `cp2`: CP2 scripts and examples.
- `backend/`: The codes we provide for you.
    - `backend/parse_http.c`: The HTTP Request / Response parser.
    - `backend/responses.c`: Predefined HTTP responses.
    - `backend/lexer.l`: Lex/Yacc related logic.
    - `backend/parser.y`
- `include/parse_http.h`
- `src/`: You need to develop here.

## 2. Environment Setup
1. Generate the binaries: `make`
2. Run the server: For example, running `./server ./cp1/test_visual/` will start an HTTP server serving the contents in `./cp1/test_visual/`.