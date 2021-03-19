package ledger

import (
	"fmt"
	"github.com/bakingbacon/hid"
	"github.com/pkg/errors"
	
	log "github.com/sirupsen/logrus"
)

type Ledger struct {
	Device  hid.DeviceInfo
	Dev     *hid.Device
	BipPath []byte
}


func Get(vendorId, productId, interfaceNumber, usagePage uint16) (*Ledger, error) {

	var tempDevice hid.DeviceInfo

	// Ledger vendor: 0x2c97 / 11415

	for _, dev := range hid.Enumerate(vendorId, productId) {
		
		log.WithFields(log.Fields{
			"ProductName": dev.Product, "Manuf": dev.Manufacturer, "Path": dev.Path, "VendorID": dev.VendorID, "ProductID": dev.ProductID,
		}).Debug("HID Device")
		
		if dev.Interface == int(interfaceNumber) || dev.UsagePage == usagePage {
			tempDevice = dev
			break
		}
	}

	if tempDevice.Path == "" {
		return nil, errors.New("Ledger plugged in? Unlocked? Correct app open?")
	}
	
	// open device
	dev, err := tempDevice.Open()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open")
	}

	if r, err := dev.SetNonBlocking(true); r == -1 {
		return nil, errors.Wrap(err, "Could not set non-blocking")
	}

	return &Ledger{
		tempDevice,
		dev,
		nil,
	}, nil
}

func (l *Ledger) Close() {
	l.Dev.Close()
}

func (l *Ledger) SetBipPath(bipPath string) (error) {

	encodedBP, err := encodeBipPath(bipPath)
	if err != nil {
		return err
	}

	// Other functions that need this path can use it
	l.BipPath = make([]byte, len(encodedBP))
	l.BipPath = encodedBP

	return nil
}

func (l *Ledger) PrintDeviceInfo() {

	fmt.Printf("Path: %s\nVID: %10d\nPID: %10d\nRelease: %10d\nUsagePage: %10d\nUsage: %10d\n" +
		"Interface: %10d\nSerial: %s\nProduct: %s\nManuf: %s\n",
		l.Device.Path, l.Device.VendorID, l.Device.ProductID, l.Device.Release, l.Device.UsagePage, l.Device.Usage, l.Device.Interface, l.Device.Serial, l.Device.Product, l.Device.Manufacturer)
}
