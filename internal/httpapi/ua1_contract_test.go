package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestUA1ProductBatchesMatchesBothPathIdentities(t *testing.T) {
	c, err := contract()
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000002"
	path := "/api/v2/r/" + id + "/warehouse/products/rice/batches"
	op, tenant := c.match("GET", path)
	if op == nil || op.id != "productBatches" || tenant != id {
		t.Fatal("UA1 nested batch path not routed to its restaurant")
	}
	r := httptest.NewRequest("GET", path+"?limit=1", nil)
	if _, err := op.validateInput(r, nil, tenant); err != nil {
		t.Fatal(err)
	}
	if another, _ := c.match("GET", path+"/extra"); another != nil {
		t.Fatal("unbounded nested path matched")
	}
}
