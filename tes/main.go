package main

import (
	"fmt"
	"log"
	"net/http"

	edumasbackend "github.com/e-dumas-sukasari/edumasbackend"
)

func Withing(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, edumasbackend.GCFGetAllReportID("PUBLICKEY","mongoenv","edumasdb", r))
}

func main() {
	handlerRequests()
}
func handlerRequests() {
	http.HandleFunc("/intersect", Withing)
	log.Fatal(http.ListenAndServe(":8080", nil))
}