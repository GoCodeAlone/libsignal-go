package session

import (
	"fmt"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/GoCodeAlone/libsignal-go/proto"
)

// SessionRecord is the persisted unit for a peer: the current SessionState plus
// a bounded list of archived (previous) sessions, each stored as the serialized
// SessionStructure bytes. Mirrors SessionRecord in
// rust/protocol/src/state/session.rs; it serializes to a RecordStructure proto.
type SessionRecord struct {
	current          *SessionState
	previousSessions [][]byte // each entry is an encoded SessionStructure
}

// NewFreshSessionRecord returns a record with no current session and no
// archives (SessionRecord::new_fresh).
func NewFreshSessionRecord() *SessionRecord {
	return &SessionRecord{}
}

// NewSessionRecord returns a record whose current session is the given state
// (SessionRecord::new).
func NewSessionRecord(state *SessionState) *SessionRecord {
	return &SessionRecord{current: state}
}

// HasCurrentState reports whether a current session is set.
func (r *SessionRecord) HasCurrentState() bool { return r.current != nil }

// CurrentState returns the current SessionState, or nil if the record is fresh.
func (r *SessionRecord) CurrentState() *SessionState { return r.current }

// SetCurrentState replaces the current session without archiving the previous
// one. Use PromoteState to archive-then-replace.
func (r *SessionRecord) SetCurrentState(state *SessionState) { r.current = state }

// PreviousSessionCount returns the number of archived sessions.
func (r *SessionRecord) PreviousSessionCount() int { return len(r.previousSessions) }

// ArchiveCurrentState moves the current session into the archived list
// (SessionRecord::archive_current_state). It is a no-op when the current
// session is already absent. The current session is encoded and prepended to
// the archive; when the archive is already at ArchivedStatesMaxLength the
// oldest (tail) entry is dropped first, matching upstream's pop-then-insert(0).
//
// Before encoding, the unacknowledged pre-key message (pending pre-key and
// pending Kyber pre-key) is cleared, matching archive_current_state_inner ->
// clear_unacknowledged_pre_key_message in session.rs: an archived session must
// not retain pending pre-key state.
func (r *SessionRecord) ArchiveCurrentState() error {
	if r.current == nil {
		// Nothing to archive; upstream treats this as a successful no-op.
		return nil
	}
	// Clear pending pre-key state on the (about-to-be-discarded) current session
	// before snapshotting it, exactly as upstream does on the taken session.
	r.current.ClearUnacknowledgedPreKeyMessage()
	encoded, err := googleproto.Marshal(r.current.structure)
	if err != nil {
		return fmt.Errorf("session: encoding current state for archive: %w", err)
	}
	if len(r.previousSessions) >= ArchivedStatesMaxLength {
		r.previousSessions = r.previousSessions[:len(r.previousSessions)-1]
	}
	r.previousSessions = append([][]byte{encoded}, r.previousSessions...)
	r.current = nil
	return nil
}

// PromoteState archives the current session (if any) and installs newState as
// the new current session (SessionRecord::promote_state).
func (r *SessionRecord) PromoteState(newState *SessionState) error {
	if err := r.ArchiveCurrentState(); err != nil {
		return err
	}
	r.current = newState
	return nil
}

// PreviousStates decodes and returns the archived SessionStates, newest first.
// A malformed archived entry returns an error.
func (r *SessionRecord) PreviousStates() ([]*SessionState, error) {
	out := make([]*SessionState, 0, len(r.previousSessions))
	for i, b := range r.previousSessions {
		var s proto.SessionStructure
		if err := googleproto.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("session: decoding archived session %d: %w", i, err)
		}
		out = append(out, NewSessionState(&s))
	}
	return out, nil
}

// PromoteOldSession moves the archived session at index oldIndex to be the
// current session, archiving whatever is currently current
// (SessionRecord::promote_old_session). oldIndex is into the
// newest-first archived list.
func (r *SessionRecord) PromoteOldSession(oldIndex int) error {
	if oldIndex < 0 || oldIndex >= len(r.previousSessions) {
		return fmt.Errorf("session: archived index %d out of range (have %d)", oldIndex, len(r.previousSessions))
	}
	encoded := r.previousSessions[oldIndex]
	var s proto.SessionStructure
	if err := googleproto.Unmarshal(encoded, &s); err != nil {
		return fmt.Errorf("session: decoding archived session %d: %w", oldIndex, err)
	}
	// Remove the chosen archived entry, then promote it (archiving current).
	r.previousSessions = append(r.previousSessions[:oldIndex], r.previousSessions[oldIndex+1:]...)
	return r.PromoteState(NewSessionState(&s))
}

// Serialize encodes the record to its RecordStructure protobuf bytes
// (SessionRecord::serialize). The archived sessions are passed through verbatim
// (they are already-encoded SessionStructure bytes).
func (r *SessionRecord) Serialize() ([]byte, error) {
	rec := &proto.RecordStructure{
		PreviousSessions: r.previousSessions,
	}
	if r.current != nil {
		rec.CurrentSession = r.current.structure
	}
	out, err := googleproto.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("session: encoding record: %w", err)
	}
	return out, nil
}

// DeserializeSessionRecord decodes a RecordStructure protobuf into a
// SessionRecord (SessionRecord::deserialize). Malformed input returns an error
// and never panics. Archived session bytes are retained opaquely; they are only
// decoded on demand (PreviousStates / PromoteOldSession).
func DeserializeSessionRecord(b []byte) (*SessionRecord, error) {
	var rec proto.RecordStructure
	if err := googleproto.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("session: decoding record: %w", err)
	}
	r := &SessionRecord{
		previousSessions: rec.GetPreviousSessions(),
	}
	if cs := rec.GetCurrentSession(); cs != nil {
		r.current = NewSessionState(cs)
	}
	return r, nil
}
