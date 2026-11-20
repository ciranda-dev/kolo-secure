// Command basic authenticates two peers on localhost and echoes a message over a stream.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	client, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}

	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", server, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	go echo(ctx, l)

	c, err := kolosecure.Dial(ctx, l.Addr().String(), client, server.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	fmt.Printf("authenticated listener %x\n", c.RemotePublicKey())

	s, err := c.OpenStream(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := s.Write([]byte("hello kolo")); err != nil {
		log.Fatal(err)
	}
	s.Close()
	reply, err := io.ReadAll(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("echo: %s\n", reply)
}

func echo(ctx context.Context, l *kolosecure.Listener) {
	c, err := l.Accept(ctx)
	if err != nil {
		return
	}
	s, err := c.AcceptStream(ctx)
	if err != nil {
		return
	}
	io.Copy(s, s)
	s.Close()
}
