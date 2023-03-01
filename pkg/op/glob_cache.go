package op

import (
	"github.com/gobwas/glob"
	lru "github.com/hashicorp/golang-lru"
)

var globCache *lru.ARCCache

func init() {
	var err error
	globCache, err = lru.NewARC(10000)
	if err != nil {
		panic(err)
	}
}

type cacheEntry struct {
	compiled glob.Glob
	err      error
}

func CompileGlob(s string) (glob.Glob, error) {
	cachedRaw, ok := globCache.Get(s)
	if ok {
		cached := cachedRaw.(cacheEntry)
		return cached.compiled, cached.err
	}
	compiled, err := glob.Compile(s)
	globCache.Add(s, cacheEntry{compiled: compiled, err: err})
	return compiled, err
}
