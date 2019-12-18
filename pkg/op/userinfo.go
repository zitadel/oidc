package op

import (
	"net/http"

	"github.com/caos/oidc/pkg/utils"
)

type UserinfoProvider interface {
	Storage() Storage
}

func Userinfo(w http.ResponseWriter, r *http.Request, userinfoProvider UserinfoProvider) {
	scopes, err := ScopesFromAccessToken(w, r)
	if err != nil {
		return
	}
	info, err := userinfoProvider.Storage().GetUserinfoFromScopes(r.Context(), scopes)
	if err != nil {
		utils.MarshalJSON(w, err)
		return
	}
	utils.MarshalJSON(w, info)
}

func ScopesFromAccessToken(w http.ResponseWriter, r *http.Request) ([]string, error) {
	return []string{}, nil
}
