// Copyright 2019 Palantir Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"encoding/xml"
)

type entityDescriptor struct {
	XMLName  xml.Name
	DS       string `xml:"xmlns:ds,attr"`
	XMLNS    string `xml:"xmlns,attr"`
	MD       string `xml:"xmlns:md,attr"`
	EntityID string `xml:"entityID,attr"`

	IDPSSODescriptor struct {
		XMLName                    xml.Name
		ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
		Keys                       []struct {
			XMLName xml.Name
			Use     string `xml:"use,attr"`
			KeyInfo struct {
				XMLName  xml.Name
				X509Data struct {
					XMLName         xml.Name
					X509Certificate struct {
						XMLName xml.Name
						Cert    string `xml:",innerxml"`
					} `xml:"X509Certificate"`
				} `xml:"X509Data"`
			} `xml:"KeyInfo"`
		} `xml:"KeyDescriptor"`
		// SingleLogoutService        SingleLogoutService `xml:"SingleLogoutService"`
		SingleSignOnServices []struct {
			XMLName  xml.Name
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
	} `xml:"IDPSSODescriptor"`
}
