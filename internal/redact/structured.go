// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"encoding/xml"
	"regexp"
	"sort"
	"strings"
)

var xmlAttrRe = regexp.MustCompile(`([A-Za-z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// RedactXML redacts selected XML element text and attribute values while
// preserving markup and all unmatched bytes.
func RedactXML(data string, m *Matcher) string {
	if m == nil || !m.Enabled() || !strings.Contains(data, "<") {
		return data
	}

	dec := xml.NewDecoder(strings.NewReader(data))
	type node struct {
		path         string
		contentStart int64
		redact       bool
	}
	var stack []node
	var spans []span

	for {
		pre := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].path
			}
			path := joinPath(parent, name)
			end := dec.InputOffset()

			rawStart := int(pre)
			rawEnd := int(end)
			if rawStart >= 0 && rawEnd <= len(data) && rawEnd > rawStart {
				tag := data[rawStart:rawEnd]
				for _, loc := range xmlAttrRe.FindAllStringSubmatchIndex(tag, -1) {
					if len(loc) < 8 || loc[2] < 0 {
						continue
					}
					attrName := tag[loc[2]:loc[3]]
					if !m.ShouldRedact(XML, path+"."+attrName) && !m.ShouldRedact(XML, attrName) {
						continue
					}
					valueStart, valueEnd := loc[4], loc[5] // double-quoted value
					if valueStart < 0 {
						valueStart, valueEnd = loc[6], loc[7] // single-quoted value
					}
					if valueStart < 0 || valueEnd <= valueStart {
						continue
					}
					spans = append(spans, span{rawStart + valueStart, rawStart + valueEnd})
				}
			}

			stack = append(stack, node{
				path:         path,
				contentStart: end,
				redact:       m.ShouldRedact(XML, path) || m.ShouldRedact(XML, name),
			})

		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if n.redact {
				spans = append(spans, span{int(n.contentStart), int(pre)})
			}
		}
	}

	return applySortedSpans(data, spans, m.Replacement())
}

var multipartNameRe = regexp.MustCompile(`(?i)name\s*=\s*(?:"([^"]*)"|([^;]+))`)

// RedactMultipart redacts selected multipart form field bodies. It preserves
// boundaries, part headers for unmatched fields and all bytes outside selected
// part bodies.
func RedactMultipart(data, boundary string, m *Matcher) string {
	if m == nil || !m.Enabled() || boundary == "" {
		return data
	}
	delim := "--" + boundary
	var spans []span
	pos := 0

	for {
		rel := strings.Index(data[pos:], delim)
		if rel < 0 {
			break
		}
		delimStart := pos + rel
		afterDelim := delimStart + len(delim)
		if strings.HasPrefix(data[afterDelim:], "--") {
			break
		}

		headerStart := afterDelim
		if strings.HasPrefix(data[headerStart:], "\r\n") {
			headerStart += 2
		} else if strings.HasPrefix(data[headerStart:], "\n") {
			headerStart++
		}

		headerEndRel := strings.Index(data[headerStart:], "\r\n\r\n")
		sepLen := 4
		if headerEndRel < 0 {
			headerEndRel = strings.Index(data[headerStart:], "\n\n")
			sepLen = 2
		}
		if headerEndRel < 0 {
			pos = afterDelim
			continue
		}
		headerEnd := headerStart + headerEndRel
		bodyStart := headerEnd + sepLen

		nextRel := strings.Index(data[bodyStart:], delim)
		if nextRel < 0 {
			break
		}
		nextDelim := bodyStart + nextRel
		bodyEnd := nextDelim
		if strings.HasSuffix(data[:bodyEnd], "\r\n") {
			bodyEnd -= 2
		} else if strings.HasSuffix(data[:bodyEnd], "\n") {
			bodyEnd--
		}

		headers := data[headerStart:headerEnd]
		if match := multipartNameRe.FindStringSubmatch(headers); match != nil {
			name := match[1]
			if name == "" {
				name = strings.TrimSpace(match[2])
			}
			if m.ShouldRedact(Form, name) {
				spans = append(spans, span{bodyStart, bodyEnd})
			}
		}

		pos = nextDelim
	}

	return applySortedSpans(data, spans, m.Replacement())
}

func applySortedSpans(data string, spans []span, replacement string) string {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	for _, sp := range spans {
		if sp.start < 0 || sp.end > len(data) || sp.start >= sp.end {
			continue
		}
		data = data[:sp.start] + replacement + data[sp.end:]
	}
	return data
}
