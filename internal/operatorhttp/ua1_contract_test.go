package operatorhttp

import "testing"

func TestUA1ResendResponseBindsInvitationResource(t *testing.T) {
	in := FacadeRequest{Method: "POST", Path: "/api/v2/orgs/00000000-0000-4000-8000-000000000001/invitations/00000000-0000-4000-8000-000000000005/resend-link", Body: []byte(`{"commandID":"link-resend"}`)}
	op, err := ValidateFacadeRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	wrong := []byte(`{"commandID":"link-resend","outcome":"committed","aggregateRevision":"9","resourceID":"00000000-0000-4000-8000-000000000099","mailJobs":[]}`)
	if err := op.ValidateResponse(in, wrong); err == nil {
		t.Fatal("resend receipt for another invitation accepted")
	}
	empty := []byte(`{"commandID":"link-resend","outcome":"committed","aggregateRevision":"9","resourceID":"00000000-0000-4000-8000-000000000005","mailJobs":[]}`)
	if err := op.ValidateResponse(in, empty); err == nil {
		t.Fatal("resend receipt without exactly one job accepted")
	}
}

func TestUA1FacadeReadsAndResendContract(t *testing.T) {
	org := "00000000-0000-4000-8000-000000000001"
	for _, in := range []FacadeRequest{
		{Method: "GET", Path: "/api/v2/orgs/" + org + "/members", RawQuery: "limit=1"},
		{Method: "GET", Path: "/api/v2/orgs/" + org + "/invitations", RawQuery: "state=all"},
		{Method: "POST", Path: "/api/v2/orgs/" + org + "/invitations/00000000-0000-4000-8000-000000000005/resend-link", Body: []byte(`{"commandID":"link-resend"}`)},
	} {
		if _, err := ValidateFacadeRequest(in); err != nil {
			t.Fatalf("UA1 operation unavailable: %s %s: %v", in.Method, in.Path, err)
		}
	}
	in := FacadeRequest{Method: "GET", Path: "/api/v2/orgs/" + org + "/members"}
	op, err := ValidateFacadeRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"context":{"orgID":"00000000-0000-4000-8000-000000000001","readerEpoch":"00000000-0000-4000-8000-000000000004","aggregateRevision":"8","evaluatedAt":"2026-10-14T15:00:00+03:00"},"items":[]}`)
	if err := op.ValidateResponse(in, valid); err != nil {
		t.Fatal(err)
	}
	wrong := []byte(`{"context":{"orgID":"00000000-0000-4000-8000-000000000099","readerEpoch":"00000000-0000-4000-8000-000000000004","aggregateRevision":"8","evaluatedAt":"2026-10-14T15:00:00+03:00"},"items":[]}`)
	if err := op.ValidateResponse(in, wrong); err == nil {
		t.Fatal("UA1 response from another organization accepted")
	}
}
