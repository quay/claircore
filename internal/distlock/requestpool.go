package distlock

type reqPool struct {
	c chan request
}

func NewReqPool(seed int) *reqPool {
	c := make(chan request, seed*2)
	for i := 0; i < seed; i++ {
		r := request{respChan: make(chan response)}
		select {
		case c <- r:
		default:

		}
	}
	return &reqPool{c}
}

func (p *reqPool) Get() request {
	select {
	case r := <-p.c:
		return r
	default:
		return request{respChan: make(chan response)}
	}
}

func (p *reqPool) Put(r request) {
	select {
	case <-r.respChan:
	default:
	}
	r.key = ""
	r.t = Invalid
	select {
	case p.c <- r:
	}
}
