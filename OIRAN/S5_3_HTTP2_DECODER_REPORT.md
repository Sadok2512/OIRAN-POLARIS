# S5.3 HTTP/2 decoder report

The native decoder validates the connection preface and frame sizes and supports SETTINGS, HEADERS, CONTINUATION, DATA, END_STREAM, RST_STREAM, GOAWAY, WINDOW_UPDATE and PING. Header blocks maintain direction-specific HPACK tables and multiplexed stream state. Frame, header, body and stream limits prevent unbounded memory use.

Malformed frames and truncated captures produce explicit partial/error states. TLS-looking flows are classified encrypted; OIRAN does not decrypt or inspect protected content.

Against TShark 4.2.2 on the unchanged corpus, OIRAN found exactly 2,316 HTTP/2 frames, matching 2,316 reference frames. It reconstructed 708 stream IDs and 198 transactions. Twenty-six header fields were unresolved where capture began after the peer had populated its HPACK dynamic table. This is not counted as an exact decode.

`HTTP2_DECODER_CERTIFIED = PASS` for the tested plaintext and deterministic cases, with the mid-connection HPACK limitation retained explicitly.
