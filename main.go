package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"
	"github.com/simplylib/multierror"
)

const certificateQuery = "SELECT certificate FROM certificate_and_identities WHERE name_value LIKE $1 ORDER BY certificate_id DESC LIMIT $2;"

// getCertificates as a slice of bytes in the der format
func getCertificates(ctx context.Context, domainName string, limit int) (certs [][]byte, err error) {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch binary_parameters=yes")
	if err != nil {
		return nil, fmt.Errorf("could not open SQL connection to postgres at crt.sh due to error (%w)", err)
	}
	defer func() {
		if err2 := db.Close(); err2 != nil {
			err = multierror.Append(err, err2)
		}
	}()

	var rows *sql.Rows
	rows, err = db.QueryContext(
		ctx,
		certificateQuery,
		domainName,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("could not execute SQL on postgres for finding certificates (%w)", err)
	}
	defer func() {
		err = multierror.Append(err, rows.Close())
	}()

	var (
		der  []byte
		ders [][]byte
	)
	for rows.Next() {
		err = rows.Scan(&der)
		if err != nil {
			return nil, fmt.Errorf("could not scan row (%w)", err)
		}

		ders = append(ders, der)
	}

	return ders, nil
}

var errExpectedArguments = errors.New("expected 1 argument: domain name")

func run() error {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	go func() {
		osSignal := make(chan os.Signal, 1)
		signal.Notify(osSignal, syscall.SIGTERM, os.Interrupt)

		s := <-osSignal
		log.Printf("Cancelling operations due to (%v)\n", s.String())
		cancelFunc()
		log.Println("operations cancelled")
	}()

	log.SetFlags(0)

	verbose := flag.Bool("v", false, "be verbose")
	limit := flag.Int("n", 1, "number of entries to return")
	printPEM := flag.Bool("pem", false, "print PEM encoded certificate")

	flag.CommandLine.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(),
			os.Args[0]+" from its domain name by querying crt.sh\n",
			"\nUsage: "+os.Args[0]+" [flags] <domain name>\n",
			"Ex: "+os.Args[0]+" github.com // print all current certificates \n",
			"\nFlags:",
		)
		flag.CommandLine.PrintDefaults()
	}

	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	if flag.NArg() != 1 {
		return errExpectedArguments
	}

	ders, err := getCertificates(ctx, flag.Args()[0], *limit)
	if err != nil {
		return fmt.Errorf("could not getCertificates of (%v) error (%w)", flag.Args()[0], err)
	}

	var cert *x509.Certificate
	for _, der := range ders {
		cert, err = x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("could not parse x509 certificate (%w)", err)
		}

		log.Printf("CommonName: (%v) Issued On: (%v)\n", cert.Subject.CommonName, cert.NotBefore)

		if *printPEM {
			err = pem.Encode(log.Default().Writer(), &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte(der),
			})
			if err != nil {
				return fmt.Errorf("could not encode PEM (%w)", err)
			}
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
