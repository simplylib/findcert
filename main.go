package main

import (
	"context"
	"database/sql"
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

const certificateQuery = `
WITH ci AS (
    SELECT min(sub.CERTIFICATE_ID) ID,
           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
           x509_commonName(sub.CERTIFICATE) COMMON_NAME,
           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
           encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
        FROM (SELECT *
                  FROM certificate_and_identities cai
                  WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
                      AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
                      AND cai.NAME_TYPE = '2.5.4.3' -- commonName
             ) sub
        GROUP BY sub.CERTIFICATE
)
SELECT ci.ISSUER_CA_ID,
        ca.NAME ISSUER_NAME,
        array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
        ci.ID ID,
        le.ENTRY_TIMESTAMP,
        ci.NOT_BEFORE,
        ci.NOT_AFTER,
        ci.SERIAL_NUMBER
    FROM ci
            LEFT JOIN LATERAL (
                SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
                    FROM ct_log_entry ctle
                    WHERE ctle.CERTIFICATE_ID = ci.ID
            ) le ON TRUE,
         ca
    WHERE ci.ISSUER_CA_ID = ca.ID
    ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST LIMIT $2;
`

func getCertificates(ctx context.Context, domainName string, limit int) ([]string, error) {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch")
	if err != nil {
		return nil, fmt.Errorf("could not open SQL connection to postgres at crt.sh due to error (%w)", err)
	}
	defer func() {
		if err2 := db.Close(); err2 != nil {
			err = multierror.Append(err, err2)
		}
	}()

	stmt, err := db.PrepareContext(ctx, certificateQuery)
	if err != nil {
		log.Printf("%T", err)
		return nil, fmt.Errorf("could not prepare SQL query (%w)", err)
	}
	defer func() {
		err = multierror.Append(err, stmt.Close())
	}()

	rows, err := stmt.QueryContext(ctx, domainName, limit)
	if err != nil {
		return nil, fmt.Errorf("could not execute SQL on postgres for finding certificates (%w)", err)
	}
	defer func() {
		err = multierror.Append(err, rows.Close())
	}()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("could not get columns (%w)", err)
	}

	_ = columns

	var (
		one   string
		two   string
		three string
		four  string
		five  string
		six   string
		seven string
		eight string
	)
	for rows.Next() {
		err = rows.Scan(&one, &two, &three, &four, &five, &six, &seven, &eight)
		if err != nil {
			return nil, fmt.Errorf("could not scan row (%w)", err)
		}

		log.Println(one, two, three, four, five, six, seven, eight)
	}

	return nil, nil
}

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
		return errors.New("expected 1 argument: domain name")
	}

	certs, err := getCertificates(ctx, flag.Args()[0], *limit)
	if err != nil {
		return fmt.Errorf("could not getCertificates of (%v) error (%w)", flag.Args()[0], err)
	}

	log.Println(certs)

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
