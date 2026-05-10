package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// TestMemberAllowedForPrivateAgent_Pure exercises the pure predicate that
// drives the private-agent gate. The gate must allow:
//   - workspace owner / admin (regardless of agent ownership)
//   - the agent owner (regardless of role)
//
// And deny everyone else. This test runs without a database.
func TestMemberAllowedForPrivateAgent_Pure(t *testing.T) {
	ownerUserID := "11111111-1111-1111-1111-111111111111"
	otherUserID := "22222222-2222-2222-2222-222222222222"

	agent := db.Agent{
		OwnerID: util.MustParseUUID(ownerUserID),
	}

	cases := []struct {
		name   string
		userID string
		role   string
		want   bool
	}{
		{"workspace owner, not agent owner", otherUserID, "owner", true},
		{"workspace admin, not agent owner", otherUserID, "admin", true},
		{"agent owner with member role", ownerUserID, "member", true},
		{"agent owner with admin role", ownerUserID, "admin", true},
		{"plain member, not agent owner", otherUserID, "member", false},
		{"plain member with no role string", otherUserID, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := memberAllowedForPrivateAgent(agent, tc.userID, tc.role)
			if got != tc.want {
				t.Fatalf("memberAllowedForPrivateAgent(userID=%s, role=%s) = %v; want %v",
					tc.userID, tc.role, got, tc.want)
			}
		})
	}
}

// privateAgentTestFixture sets up a private agent owned by a freshly created
// user, plus a second non-admin member in the workspace. Returns the agent
// id, the owner's user id, and the unrelated member's user id. The caller's
// own testUserID stays workspace owner so it can act as the privileged
// admin path.
func privateAgentTestFixture(t *testing.T) (agentID, ownerID, memberID string) {
	t.Helper()

	ctx := context.Background()
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user" (name, email)
		VALUES ('Private Agent Owner', 'private-agent-owner@multica.test')
		RETURNING id
	`).Scan(&ownerID); err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(),
			`DELETE FROM "user" WHERE email = 'private-agent-owner@multica.test'`)
	})

	if _, err := testPool.Exec(ctx, `
		INSERT INTO member (workspace_id, user_id, role)
		VALUES ($1, $2, 'member')
	`, testWorkspaceID, ownerID); err != nil {
		t.Fatalf("add owner as member: %v", err)
	}

	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user" (name, email)
		VALUES ('Plain Member', 'plain-member@multica.test')
		RETURNING id
	`).Scan(&memberID); err != nil {
		t.Fatalf("create plain member user: %v", err)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(),
			`DELETE FROM "user" WHERE email = 'plain-member@multica.test'`)
	})

	if _, err := testPool.Exec(ctx, `
		INSERT INTO member (workspace_id, user_id, role)
		VALUES ($1, $2, 'member')
	`, testWorkspaceID, memberID); err != nil {
		t.Fatalf("add plain member: %v", err)
	}

	if err := testPool.QueryRow(ctx, `
		INSERT INTO agent (
			workspace_id, name, description, runtime_mode, runtime_config,
			runtime_id, visibility, max_concurrent_tasks, owner_id,
			instructions, custom_env, custom_args
		)
		VALUES ($1, 'private-access-test-agent', '', 'cloud', '{}'::jsonb,
		        $2, 'private', 1, $3, '', '{}'::jsonb, '[]'::jsonb)
		RETURNING id
	`, testWorkspaceID, handlerTestRuntimeID(t), ownerID).Scan(&agentID); err != nil {
		t.Fatalf("create private agent: %v", err)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(),
			`DELETE FROM agent WHERE id = $1`, agentID)
	})

	return agentID, ownerID, memberID
}

func newRequestAs(userID, method, path string, body any) *http.Request {
	req := newRequest(method, path, body)
	req.Header.Set("X-User-ID", userID)
	return req
}

// TestGetAgent_PrivateAgentForbidsPlainMember verifies the private-agent
// visibility gate at the read-detail endpoint: a workspace member who is
// neither the agent owner nor a workspace owner/admin gets 403, while the
// agent owner and workspace owner both succeed. Mirrors the four-entry-point
// gate (chat, history, edit, delete) on its read surface.
func TestGetAgent_PrivateAgentForbidsPlainMember(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	agentID, ownerID, memberID := privateAgentTestFixture(t)

	// Workspace owner (testUserID): allowed via role.
	w := httptest.NewRecorder()
	testHandler.GetAgent(w, withURLParam(newRequest("GET", "/api/agents/"+agentID, nil), "id", agentID))
	if w.Code != http.StatusOK {
		t.Fatalf("GetAgent as workspace owner: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Agent owner (plain member who happens to own the agent): allowed.
	w = httptest.NewRecorder()
	testHandler.GetAgent(w, withURLParam(newRequestAs(ownerID, "GET", "/api/agents/"+agentID, nil), "id", agentID))
	if w.Code != http.StatusOK {
		t.Fatalf("GetAgent as agent owner: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Plain member (not in allowed_principals): denied with 403.
	w = httptest.NewRecorder()
	testHandler.GetAgent(w, withURLParam(newRequestAs(memberID, "GET", "/api/agents/"+agentID, nil), "id", agentID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("GetAgent as plain member: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestListAgents_FiltersPrivateForPlainMember verifies that the workspace
// agents listing hides private agents from members who lack access. This is
// what makes the @-mention autocomplete picker (which feeds off this list)
// drop unreachable private agents without any client-side logic.
func TestListAgents_FiltersPrivateForPlainMember(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	agentID, _, memberID := privateAgentTestFixture(t)

	// Workspace owner sees the agent.
	w := httptest.NewRecorder()
	testHandler.ListAgents(w, newRequest("GET", "/api/agents", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListAgents as owner: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !listContainsAgent(t, w.Body.Bytes(), agentID) {
		t.Fatalf("ListAgents as owner did not include private agent %s", agentID)
	}

	// Plain member does NOT see the agent.
	w = httptest.NewRecorder()
	testHandler.ListAgents(w, newRequestAs(memberID, "GET", "/api/agents", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListAgents as plain member: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if listContainsAgent(t, w.Body.Bytes(), agentID) {
		t.Fatalf("ListAgents as plain member leaked private agent %s", agentID)
	}
}

func listContainsAgent(t *testing.T, body []byte, agentID string) bool {
	t.Helper()
	var resp []AgentResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode ListAgents response: %v", err)
	}
	for _, a := range resp {
		if a.ID == agentID {
			return true
		}
	}
	return false
}

// TestListAgentTasks_PrivateAgentForbidsPlainMember verifies that the agent
// task history endpoint (the "查看历史会话" surface) is also gated.
func TestListAgentTasks_PrivateAgentForbidsPlainMember(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	agentID, ownerID, memberID := privateAgentTestFixture(t)

	w := httptest.NewRecorder()
	testHandler.ListAgentTasks(w, withURLParam(newRequestAs(ownerID, "GET", "/api/agents/"+agentID+"/tasks", nil), "id", agentID))
	if w.Code != http.StatusOK {
		t.Fatalf("ListAgentTasks as owner: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	testHandler.ListAgentTasks(w, withURLParam(newRequestAs(memberID, "GET", "/api/agents/"+agentID+"/tasks", nil), "id", agentID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ListAgentTasks as plain member: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateIssue_AssignToPrivateAgentForbidsPlainMember verifies that the
// issue-assignment surface is gated by the same predicate. Without this gate
// a plain workspace member could side-step chat/@-mention by assigning a
// private agent to an issue and letting normal task dispatch run it.
func TestCreateIssue_AssignToPrivateAgentForbidsPlainMember(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	agentID, ownerID, memberID := privateAgentTestFixture(t)

	body := func(actorID string) map[string]any {
		return map[string]any{
			"title":         "assign-to-private-agent test " + actorID,
			"status":        "todo",
			"priority":      "medium",
			"assignee_type": "agent",
			"assignee_id":   agentID,
		}
	}

	// Workspace owner (testUserID): allowed.
	w := httptest.NewRecorder()
	testHandler.CreateIssue(w, newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, body(testUserID)))
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateIssue as workspace owner: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Agent owner (plain member who happens to own the agent): allowed.
	w = httptest.NewRecorder()
	testHandler.CreateIssue(w, newRequestAs(ownerID, "POST", "/api/issues?workspace_id="+testWorkspaceID, body(ownerID)))
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateIssue as agent owner: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Plain member: denied with 403 — closes the back door where issue
	// assignment would otherwise hand the agent a task without going
	// through chat / @-mention.
	w = httptest.NewRecorder()
	testHandler.CreateIssue(w, newRequestAs(memberID, "POST", "/api/issues?workspace_id="+testWorkspaceID, body(memberID)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("CreateIssue as plain member: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateChatSession_PrivateAgentForbidsPlainMember verifies that members
// who can't access the private agent cannot start a chat session against it.
// The chat handler reads workspace context from middleware, so we set it
// explicitly via middleware.SetMemberContext before invoking the handler
// (the test harness doesn't run the real middleware chain).
func TestCreateChatSession_PrivateAgentForbidsPlainMember(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	agentID, _, memberID := privateAgentTestFixture(t)

	// Load the plain member's row so we can build a realistic context.
	memberRow, err := testHandler.Queries.GetMemberByUserAndWorkspace(context.Background(), db.GetMemberByUserAndWorkspaceParams{
		UserID:      util.MustParseUUID(memberID),
		WorkspaceID: util.MustParseUUID(testWorkspaceID),
	})
	if err != nil {
		t.Fatalf("load plain member row: %v", err)
	}

	body := map[string]any{
		"agent_id": agentID,
		"title":    "should be denied",
	}
	w := httptest.NewRecorder()
	req := newRequestAs(memberID, "POST", "/api/chat/sessions", body)
	req = req.WithContext(middleware.SetMemberContext(req.Context(), testWorkspaceID, memberRow))
	testHandler.CreateChatSession(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("CreateChatSession as plain member: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
