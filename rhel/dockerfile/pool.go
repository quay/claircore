package dockerfile

import "sync"

var parserPool sync.Pool

func getParser() *labelParser {
	v := parserPool.Get()
	if v != nil {
		return v.(*labelParser)
	}
	return newLabelParser()
}

func putParser(p *labelParser) {
	parserPool.Put(p)
}
