package execupdater

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"

	"github.com/quay/zlog"
	"golang.org/x/exp/jsonrpc2"
)

var _ jsonrpc2.Listener = (*stdioExec)(nil)

func execListener(cmd *exec.Cmd) *stdioExec {
	return &stdioExec{cmd}
}

type stdioExec struct {
	cmd *exec.Cmd
}

func (l *stdioExec) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	// If the process is already started, return EOF.
	if l.cmd.Process != nil || l.cmd.ProcessState != nil {
		return nil, io.EOF
	}

	var err error
	var logs io.Reader
	var p procPipe
	p.cmd = l.cmd
	p.cmd.Stdin, p.egress, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	p.ingress, p.cmd.Stdout, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	logs, p.cmd.Stderr, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	ctx, p.done = context.WithCancel(ctx)
	go p.logger(ctx, logs)
	if err := p.cmd.Start(); err != nil {
		p.done()
		return nil, err
	}

	return &p, nil
}

func (l *stdioExec) Close() error {
	return l.cmd.Wait()
}

func (l *stdioExec) Dialer() jsonrpc2.Dialer { return nil }

var _ io.ReadWriteCloser = (*procPipe)(nil)

type procPipe struct {
	cmd     *exec.Cmd
	egress  *os.File
	ingress *os.File
	logs    *os.File
	done    context.CancelFunc
}

func (p *procPipe) Read(b []byte) (int, error) {
	return p.ingress.Read(b)
}

func (p *procPipe) Write(b []byte) (int, error) {
	return p.egress.Write(b)
}

func (p *procPipe) Close() error {
	p.done()
	return p.cmd.Wait()
}

func (p *procPipe) logger(ctx context.Context, f io.Reader) {
	s := bufio.NewScanner(f)
	for s.Scan() {
		b := s.Bytes()
		ev := zlog.Info(ctx)
		if json.Valid(b) {
			ev.RawJSON("log", b)
		} else {
			ev.Str("line", s.Text())
		}
		ev.Send()
	}
	if err := s.Err(); err != nil {
		zlog.Warn(ctx).Err(err).Msg("unexpected error reading log stream")
	}
}
