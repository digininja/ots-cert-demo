package main

/*
References

Example DNS code
https://github.com/cloudflare/cloudflare-go/blob/master/dns_example_test.go

This is the DNS code with the functions and declarations in it
https://github.com/cloudflare/cloudflare-go/blob/master/dns.go

This is the cloudflare API spec
https://api.cloudflare.com/#dns-records-for-a-zone-update-dns-record
*/

import (
	"errors"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
)
import log "github.com/sirupsen/logrus"

func DeleteDNSRecord(entryType string, name string) error {
	log.Debugf(fmt.Sprintf("Delete is fetching a %s record with the name %s\n", entryType, name))

	// record is used as a filter to say what to bring back, here it is set
	// to the entry type and name that is needed
	record := cloudflare.DNSRecord{Type: entryType, Name: name}

	// do the search
	recs, err := api.DNSRecords(zoneID, record)
	if err != nil {
		log.Debug("The record wasn't found, nothing to delete")
		return nil
	}

	log.Debugf(fmt.Sprintf("Number of records found: %d\n", len(recs)))

	if len(recs) == 0 {
		log.Print("No records returned, nothing to delete")
		return nil
	}
	for _, r := range recs {
		log.Debugf(fmt.Sprintf("Record to delete - %s: %s (%s)\n", r.Name, r.Content, r.ID))

		recordID := r.ID

		err = api.DeleteDNSRecord(zoneID, recordID)
		if err != nil {
			log.Debugf("Something went wrong with the delete: %s", err)
			return errors.New(fmt.Sprintf("Something went wrong with the delete: %s", err.Error()))
		}
	}
	return nil
}

func CreateOrUpdateDNSRecord(entryType string, name string, content string) error {
	log.Debugf("Create or update DNS record, %s containing %s of type %s", name, content, entryType)

	// record is used as a filter to say what to bring back, here it is set
	// to the entry type and name that is needed
	record := cloudflare.DNSRecord{Type: entryType, Name: name}

	// do the search
	recs, err := api.DNSRecords(zoneID, record)
	if err != nil {
		log.Debug("Searching for existing record failed")
		return errors.New("Searching for existing record failed")
	}

	log.Debugf(fmt.Sprintf("Number of records found: %d\n", len(recs)))
	log.Debugf("%u", recs)

	if len(recs) > 0 {
		log.Debugf("Record already exists - doing an update")

		for _, r := range recs {
			log.Debugf(fmt.Sprintf("Record to update - %s: %s (%s)\n", r.Name, r.Content, r.ID))

			responseID := r.ID

			// this contains the new information, in this case
			// it is just the content
			record := cloudflare.DNSRecord{}
			record.Content = content

			err = api.UpdateDNSRecord(zoneID, responseID, record)
			if err != nil {
				log.Debugf("Failed to update the DNS record, error: %s", err)
				return errors.New("Failed to update the DNS record")
			}
		}
	} else {
		log.Debugf("Record does not already exist - creating it")

		// set up the new record
		record := cloudflare.DNSRecord{}
		record.Type = entryType
		record.Name = name
		record.Content = content

		_, err := api.CreateDNSRecord(zoneID, record)
		if err != nil {
			log.Debugf("Failed to add the DNS record, error: %s", err)
			return errors.New("Failed to add the DNS record")
		}
	}
	return nil
}

func getUserDetails() {
	log.Debug("Getting user details")
	// Fetch user details on the account
	u, err := api.UserDetails()
	if err != nil {
		log.Fatalf("Error getting user details, error: %s", err)
	}
	// Print user details
	log.Debugf("User details: %u", u)
}

func CheckRecord(recordType string, name string) bool {
	// Fetch all records for a zone
	log.Debugf("Looking for the record %s of type %s", name, recordType)

	record := cloudflare.DNSRecord{
		Type: recordType,
		Name: name,
	}
	// Can filter like this when creating
	// record := cloudflare.DNSRecord{Type: "TXT"}
	// or
	// record.Type = "TXT

	recs, err := api.DNSRecords(zoneID, record)
	if err != nil {
		log.Debugf("There was an error: %s", err.Error())
		return false
	}
	log.Debugf("Found %d record(s)", len(recs))

	return len(recs) > 0
}

func DumpDNSEntries() {
	// Fetch all records for a zone
	log.Debug("Dumping all the records")

	record := cloudflare.DNSRecord{}
	// Can filter like this when creating
	// record := cloudflare.DNSRecord{Type: "TXT"}
	// or
	// record.Type = "TXT

	recs, err := api.DNSRecords(zoneID, record)
	if err != nil {
		log.Debugf("There was an error: %s", err.Error())
		return
	}

	for _, r := range recs {
		log.Debugf("%s: %s %s (%s)\n", r.Name, r.Type, r.Content, r.ID)
	}
}

var zoneID string
var api *cloudflare.API

func InitCloudflare() {
	var err error
	log.Debug("Init Cloudflare DNS module")

	// Construct a new API object
	api, err = cloudflare.New(Cfg.CloudflareCreds.API_Key, Cfg.CloudflareCreds.API_Email)
	if err != nil {
		log.Fatalf("Error creating Cloudflare object, error: %s", err)
	}

	// Fetch the zone ID
	id, err := api.ZoneIDByName(Cfg.Domain)
	if err != nil {
		log.Fatalf("Error fetching zone ID, error: %s", err)
	}

	// Fetch zone details
	zone, err := api.ZoneDetails(id)
	if err != nil {
		log.Fatal("Error fetching zone details, error: %s", err)
	}
	zoneID = zone.ID

	// Print zone details
	log.Debugf("The zone ID is %s\n", zone.ID)
}
