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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/pkg/errors"
)

const (
	HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
)

type OnErrorCallback func(*http.Request, error)

type OnLoginCallback func(http.ResponseWriter, *http.Request, *saml.Response)

type Settings struct {
	AssertionConsumerServicePath string
	SignRequests                 bool
	SigningCertificatePath       string
	SigningKeyPath               string
	IDPMetadataURL               string
	OnError                      OnErrorCallback
	OnLogin                      OnLoginCallback
}

// ServiceProvider is capable of handling a SAML login. It provides
// an http.Handler (via ACSHandler) which can process the http POST from the SAML IDP. It accepts callbacks for both error and
// success conditions so that clients can take action after the auth flow is complete. It also provides a handler
// for serving the service provider metadata XML.
type ServiceProvider struct {
	settings *saml.ServiceProviderSettings
	acsPath  string
	onError  OnErrorCallback
	onLogin  OnLoginCallback
}

// NewServiceProviderFromMetadata returns a ServiceProvider. The configuration of the ServiceProvider
// is a result of combinging settings provided to this method and values parsed from the IDP's metadata.
func NewServiceProviderFromMetadata(settings Settings) (*ServiceProvider, error) {
	s, err := getSettingsFromMetadata(settings)
	if err != nil {
		return nil, errors.Wrap(err, "could not determine settings from IDP metadata")
	}
	sp := &ServiceProvider{
		settings: s,
		onError:  settings.OnError,
		onLogin:  settings.OnLogin,
		acsPath:  settings.AssertionConsumerServicePath,
	}

	if sp.onError == nil {
		sp.onError = DefaultErrorCallback
	}

	if sp.onLogin == nil {
		sp.onLogin = DefaultLoginCallback
	}

	return sp, nil
}

func DefaultErrorCallback(r *http.Request, err error) {
	fmt.Println(err.Error())
}

func DefaultLoginCallback(w http.ResponseWriter, r *http.Request, resp *saml.Response) {
	w.WriteHeader(http.StatusOK)
}

func getSettingsFromMetadata(settings Settings) (*saml.ServiceProviderSettings, error) {
	resp, err := http.Get(settings.IDPMetadataURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download IDP metadata")
	}

	defer func() { _ = resp.Body.Close() }()
	descriptor, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download IDP metadata")
	}

	entity := &entityDescriptor{}

	if err := xml.Unmarshal(descriptor, entity); err != nil {
		return nil, errors.Wrap(err, "could not parse returned metadata")
	}

	//Write signing key to temporary file
	f, err := ioutil.TempFile("", "idpCert")
	if err != nil {
		return nil, errors.Wrap(err, "failed to save IDP certificate to disk")
	}

	//find the singing key
	var key string
	for _, k := range entity.IDPSSODescriptor.Keys {
		if k.Use == "signing" {
			key = k.KeyInfo.X509Data.X509Certificate.Cert
		}
	}

	if key == "" {
		return nil, errors.New("failed to find signing key in IDP metadata")
	}

	if _, err := f.WriteString(key); err != nil {
		return nil, errors.Wrap(err, "failed to save IDP certificate to disk")
	}

	if err := f.Close(); err != nil {
		return nil, errors.Wrap(err, "failed to close temporary file")
	}

	//Get SSO URL
	//Currently only support redirect
	// TODO(maybe?) Support HTTP-POST binding

	var idpURL string
	for _, a := range entity.IDPSSODescriptor.SingleSignOnServices {
		if a.Binding == HTTPRedirectBinding {
			idpURL = a.Location
		}
	}

	if idpURL == "" {
		return nil, errors.New("failed to find redirect ACS for IDP")
	}

	s := &saml.ServiceProviderSettings{
		IDPSSOURL:         idpURL,
		IDPPublicCertPath: f.Name(),
		SPSignRequest:     settings.SignRequests,
		PublicCertPath:    settings.SigningCertificatePath,
		PrivateKeyPath:    settings.SigningKeyPath,
	}

	return s, errors.Wrap(s.Init(), "failed to load certificates")

}

func (s *ServiceProvider) getSAMLSettingsForRequest(r *http.Request) *saml.ServiceProviderSettings {

	//make a copy in case different requests have different host headers
	newSettings := *s.settings

	u := &url.URL{
		Host:   r.Host,
		Scheme: "http",
	}

	if r.TLS != nil {
		u.Scheme = "https"
	}

	newSettings.IDPSSODescriptorURL = u.String()
	u.Path = s.acsPath
	newSettings.AssertionConsumerServiceURL = u.String()

	return &newSettings
}

// DoAuth takes an http.ResponseWriter that has not been written to yet, and conducts and SP initiated login
// If the flow proceeds correctly the user should be redirected to the handler provided by ACSHandler().
func (s *ServiceProvider) DoAuth(w http.ResponseWriter, r *http.Request, state string) {
	settings := s.getSAMLSettingsForRequest(r)

	request := settings.GetAuthnRequest()

	//construct current hostname/protocol to use as the EntityID

	b64xml, err := request.CompressedEncodedString()
	if err != nil {
		s.onError(r, errors.Wrap(err, "failed to encode auth request"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	target, err := saml.GetAuthnRequestURL(settings.IDPSSOURL, b64xml, state)
	if err != nil {
		s.onError(r, errors.Wrap(err, "failed to build redirect URL"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, target, http.StatusFound)
}

// ACSHandler returns an http.Handler which is capable of validating and processing SAML Responses.
func (s *ServiceProvider) ACSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodedXML := r.FormValue("SAMLResponse")

		if encodedXML == "" {
			// no onError call because not getting an assertion is probably just a bad redirect/refresh not an integration issue
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		response, err := saml.ParseEncodedResponse(encodedXML)
		if err != nil {
			s.onError(r, errors.Wrap(err, "failed to parse saml assertion"))
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		if err := response.Validate(s.getSAMLSettingsForRequest(r)); err != nil {
			s.onError(r, errors.Wrap(err, "failed to validate saml assertion"))
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		s.onLogin(w, r, response)
	})

}

// MetadataHandler returns an http.Handler which sends the generated metadata XML in response to a request
func (s *ServiceProvider) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md, err := s.getSAMLSettingsForRequest(r).GetEntityDescriptor()
		if err != nil {
			s.onError(r, errors.Wrap(err, "failed to generate service provider metadata"))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		if _, err := w.Write([]byte(md)); err != nil {
			s.onError(r, errors.Wrap(err, "failed to write metadta to response"))
		}
	})
}
