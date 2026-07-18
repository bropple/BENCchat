package oscar

import (
	"bytes"
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

func dirResultBlock(sn, first, last, city string) wire.TLVBlock {
	return wire.TLVBlock{TLVList: wire.TLVList{
		wire.NewTLVBE(wire.ODirTLVFirstName, []byte(first)),
		wire.NewTLVBE(wire.ODirTLVLastName, []byte(last)),
		wire.NewTLVBE(wire.ODirTLVCity, []byte(city)),
		wire.NewTLVBE(wire.ODirTLVScreenName, []byte(sn)),
	}}
}

// A successful multi-result reply must decode to its rows, matching each field
// back to the right result. The count-prefixed list of TLV blocks is the fiddly
// part — an off-by-one there silently merges or drops rows.
func TestDecodeDirReplyResults(t *testing.T) {
	reply := wire.SNAC_0x0F_0x03_InfoReply{
		Status: wire.ODirStatusOK,
		Results: []wire.TLVBlock{
			dirResultBlock("rtriy", "R.", "Triy", "Phoenix"),
			dirResultBlock("alice", "U", "Sec", "Portland"),
		},
	}
	var buf bytes.Buffer
	if err := wire.MarshalBE(reply, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}

	results, ok, err := DecodeDirReply(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeDirReply: %v", err)
	}
	if !ok {
		t.Fatal("ok = false for an OK-status reply")
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].ScreenName != "rtriy" || results[0].LastName != "Triy" || results[0].City != "Phoenix" {
		t.Fatalf("result[0] fields wrong: %+v", results[0])
	}
	if results[1].ScreenName != "alice" || results[1].FirstName != "U" {
		t.Fatalf("result[1] fields wrong: %+v", results[1])
	}
}

// An OK search with no matches decodes to zero rows, still ok — distinct from a
// failed search.
func TestDecodeDirReplyEmpty(t *testing.T) {
	reply := wire.SNAC_0x0F_0x03_InfoReply{Status: wire.ODirStatusOK}
	var buf bytes.Buffer
	if err := wire.MarshalBE(reply, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	results, ok, err := DecodeDirReply(buf.Bytes())
	if err != nil || !ok {
		t.Fatalf("empty OK reply: ok=%v err=%v", ok, err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
}

// A non-OK status (e.g. name missing) yields ok=false and no rows, so the UI can
// tell "search couldn't run" from "ran, matched nobody".
func TestDecodeDirReplyNameMissing(t *testing.T) {
	reply := wire.SNAC_0x0F_0x03_InfoReply{Status: wire.ODirStatusNameMissing}
	var buf bytes.Buffer
	if err := wire.MarshalBE(reply, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, ok, err := DecodeDirReply(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok {
		t.Fatal("ok = true for a name-missing status")
	}
}

// The query the client sends must marshal cleanly and carry the name TLVs the
// server keys its search on.
func TestSearchQueryMarshals(t *testing.T) {
	q := wire.SNAC_0x0F_0x02_InfoQuery{TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
		wire.NewTLVBE(wire.ODirTLVFirstName, []byte("R.")),
		wire.NewTLVBE(wire.ODirTLVLastName, []byte("Triy")),
	}}}
	var buf bytes.Buffer
	if err := wire.MarshalBE(q, &buf); err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	var got wire.SNAC_0x0F_0x02_InfoQuery
	if err := wire.UnmarshalBE(&got, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal query: %v", err)
	}
	if name, ok := got.String(wire.ODirTLVLastName); !ok || name != "Triy" {
		t.Fatalf("last-name TLV round-trip: %q ok=%v", name, ok)
	}
}
