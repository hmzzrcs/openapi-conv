package openapi_conv

import (
	openapi3_2 "github.com/getkin/kin-openapi/openapi3"
	openapi3 "github.com/hmzzrcs/go-openapi"
)

func ConvT(src *openapi3_2.T) *openapi3.T {
	if src == nil {
		return nil
	}
	t := &openapi3.T{
		OpenAPI:    src.OpenAPI,
		Components: convComponents(src.Components),
		Info:       convInfo(src.Info),
		Paths:      convPaths(src.Paths),
		Security: convArray(src.Security, func(v openapi3_2.SecurityRequirement) openapi3.SecurityRequirement {
			return openapi3.SecurityRequirement(v)
		}),
		Servers:      convArray(src.Servers, convServer),
		Tags:         convArray(src.Tags, convTag),
		ExternalDocs: convExternalDocs(src.ExternalDocs),
	}

	return CopyExtensions(t, src.Extensions)
}

func convPaths(paths *openapi3_2.Paths) *openapi3.Paths {
	if paths == nil {
		return nil
	}
	np := openapi3.NewPaths()
	for k, v := range paths.Map() {
		np.Set(k, convPathItem(v))
	}
	return CopyExtensions(np, paths.Extensions)
}

func convTag(v *openapi3_2.Tag) *openapi3.Tag {
	if v == nil {
		return nil
	}
	return CopyExtensions(&openapi3.Tag{
		Name:         v.Name,
		Description:  v.Description,
		ExternalDocs: convExternalDocs(v.ExternalDocs),
	}, v.Extensions)
}

func convInfo(info *openapi3_2.Info) *openapi3.Info {
	if info == nil {
		return nil
	}
	return CopyExtensions(&openapi3.Info{
		Title:          info.Title,
		Description:    info.Description,
		TermsOfService: info.TermsOfService,
		Contact:        convContact(info.Contact),
		License:        convLicense(info.License),
		Version:        info.Version,
	}, info.Extensions)
}

func convLicense(license *openapi3_2.License) *openapi3.License {
	if license == nil {
		return nil
	}
	return CopyExtensions(&openapi3.License{
		Name: license.Name,
		URL:  license.URL,
	}, license.Extensions)
}

func convContact(contact *openapi3_2.Contact) *openapi3.Contact {
	if contact == nil {
		return nil
	}
	return CopyExtensions(&openapi3.Contact{
		Name:  contact.Name,
		URL:   contact.URL,
		Email: contact.Email,
	}, contact.Extensions)
}

func convComponents(src *openapi3_2.Components) *openapi3.Components {
	if src == nil {
		return nil
	}
	t := &openapi3.Components{
		Schemas:         convMap(src.Schemas, convSchemaRef),
		Parameters:      convMap(src.Parameters, convParameterRef),
		Headers:         convMap(src.Headers, convHeaderRef),
		RequestBodies:   convMap(src.RequestBodies, convRequestBodyRef),
		Responses:       convMap(src.Responses, convResponseRef),
		SecuritySchemes: convMap(src.SecuritySchemes, convSecuritySchemeRef),
		Examples:        convMap(src.Examples, convExampleRef),
		Links:           convMap(src.Links, convLinkRef),
		Callbacks:       convMap(src.Callbacks, convCallbackRef),
	}

	return CopyExtensions(t, src.Extensions)
}

func convSecuritySchemeRef(v *openapi3_2.SecuritySchemeRef) *openapi3.SecuritySchemeRef {
	if v == nil {
		return nil
	}
	return &openapi3.SecuritySchemeRef{
		Ref:   v.Ref,
		Value: convSecurityScheme(v.Value),
	}
}

func convSecurityScheme(value *openapi3_2.SecurityScheme) *openapi3.SecurityScheme {
	if value == nil {
		return nil
	}
	t := &openapi3.SecurityScheme{
		Type:             value.Type,
		Description:      value.Description,
		Name:             value.Name,
		In:               value.In,
		Scheme:           value.Scheme,
		BearerFormat:     value.BearerFormat,
		Flows:            convOAuthFlows(value.Flows),
		OpenIdConnectUrl: value.OpenIdConnectUrl,
	}

	return CopyExtensions(t, value.Extensions)
}

func convOAuthFlows(flows *openapi3_2.OAuthFlows) *openapi3.OAuthFlows {
	if flows == nil {
		return nil
	}
	t := &openapi3.OAuthFlows{
		Implicit:          convOAuthFlow(flows.Implicit),
		Password:          convOAuthFlow(flows.Password),
		ClientCredentials: convOAuthFlow(flows.ClientCredentials),
		AuthorizationCode: convOAuthFlow(flows.AuthorizationCode),
	}
	return CopyExtensions(t, flows.Extensions)
}

func convOAuthFlow(v *openapi3_2.OAuthFlow) *openapi3.OAuthFlow {
	if v == nil {
		return nil
	}
	return CopyExtensions(&openapi3.OAuthFlow{
		AuthorizationURL: v.AuthorizationURL,
		TokenURL:         v.TokenURL,
		RefreshURL:       v.RefreshURL,
		Scopes:           v.Scopes,
	}, v.Extensions)
}

func convCallbackRef(v *openapi3_2.CallbackRef) *openapi3.CallbackRef {
	if v == nil {
		return nil
	}
	return &openapi3.CallbackRef{
		Ref:   v.Ref,
		Value: convCallBack(v.Value),
	}
}

func convCallBack(value *openapi3_2.Callback) *openapi3.Callback {
	if value == nil {
		return nil
	}
	n := &openapi3.Callback{}
	for k, v := range convMap(value.Map(), convPathItem) {
		n.Set(k, v)
	}
	return CopyExtensions(n, value.Extensions)
}
func convPathItem(v *openapi3_2.PathItem) *openapi3.PathItem {
	if v == nil {
		return nil
	}
	return CopyExtensions(&openapi3.PathItem{
		Ref:         v.Ref,
		Summary:     v.Summary,
		Description: v.Description,
		Connect:     convOperation(v.Connect),
		Delete:      convOperation(v.Delete),
		Get:         convOperation(v.Delete),
		Head:        convOperation(v.Head),
		Options:     convOperation(v.Options),
		Patch:       convOperation(v.Patch),
		Post:        convOperation(v.Post),
		Put:         convOperation(v.Put),
		Trace:       convOperation(v.Trace),
		Servers:     convArray(v.Servers, convServer),
		Parameters:  convArray(v.Parameters, convParameterRef),
	}, v.Extensions)
}

func convServer(v *openapi3_2.Server) *openapi3.Server {
	return CopyExtensions(&openapi3.Server{
		URL:         v.URL,
		Description: v.Description,
		Variables:   convMap(v.Variables, convServerVariable),
	}, v.Extensions)
}

func convServerVariable(v *openapi3_2.ServerVariable) *openapi3.ServerVariable {
	if v == nil {
		return nil
	}

	return CopyExtensions(&openapi3.ServerVariable{
		Enum:        v.Enum,
		Default:     v.Default,
		Description: v.Description,
	}, v.Extensions)
}

func convOperation(connect *openapi3_2.Operation) *openapi3.Operation {
	if connect == nil {
		return nil
	}
	return CopyExtensions(&openapi3.Operation{
		Tags:        connect.Tags,
		Summary:     connect.Summary,
		Description: connect.Description,
		OperationID: connect.OperationID,
		Parameters:  convArray(connect.Parameters, convParameterRef),
		RequestBody: convRequestBodyRef(connect.RequestBody),
		Responses:   convResponses(connect.Responses),
		Callbacks:   convMap(connect.Callbacks, convCallbackRef),
		Deprecated:  connect.Deprecated,
		Security:    convSecurityRequirements(connect.Security),
		Servers: func() *openapi3.Servers {
			if connect.Servers == nil {
				return nil
			}
			n := openapi3.Servers(convArray(*connect.Servers, convServer))
			return &n
		}(),
		ExternalDocs: convExternalDocs(connect.ExternalDocs),
	}, connect.Extensions)
}

func convExternalDocs(docs *openapi3_2.ExternalDocs) *openapi3.ExternalDocs {
	if docs == nil {
		return nil
	}
	return CopyExtensions(&openapi3.ExternalDocs{
		Description: docs.Description,
		URL:         docs.URL,
	}, docs.Extensions)
}

func convSecurityRequirements(security *openapi3_2.SecurityRequirements) *openapi3.SecurityRequirements {
	if security == nil {
		return nil
	}

	n := openapi3.SecurityRequirements(convArray(*security, func(v openapi3_2.SecurityRequirement) openapi3.SecurityRequirement {
		return convMap(v, func(v []string) []string {
			return v
		})
	}))

	return &n

}

func convResponses(responses *openapi3_2.Responses) *openapi3.Responses {
	if responses == nil {
		return nil
	}
	m := responses.Map()
	n := &openapi3.Responses{}
	for k, v := range m {
		n.Set(k, convResponseRef(v))
	}
	return CopyExtensions(n, responses.Extensions)
}
func convResponseRef(resp *openapi3_2.ResponseRef) *openapi3.ResponseRef {
	if resp == nil {
		return nil
	}
	return &openapi3.ResponseRef{
		Ref:   resp.Ref,
		Value: convResponse(resp.Value),
	}
}
func convResponse(v *openapi3_2.Response) *openapi3.Response {
	if v == nil {
		return nil
	}
	n := &openapi3.Response{
		Description: v.Description,
		Headers:     convMap(v.Headers, convHeaderRef),
		Content:     convMap(v.Content, convMediaType),
		Links:       convMap(v.Links, convLinkRef),
	}
	return CopyExtensions(
		n,
		v.Extensions,
	)
}

func convLinkRef(v *openapi3_2.LinkRef) *openapi3.LinkRef {
	if v == nil {
		return nil
	}
	return &openapi3.LinkRef{
		Ref:   v.Ref,
		Value: convLink(v.Value),
	}
}

func convLink(value *openapi3_2.Link) *openapi3.Link {
	return CopyExtensions(&openapi3.Link{
		OperationRef: value.OperationRef,
		OperationID:  value.OperationID,
		Description:  value.Description,
		Parameters:   value.Parameters,
		Server:       convServer(value.Server),
		RequestBody:  value.RequestBody,
	}, value.Extensions)
}
func convRequestBodyRef(body *openapi3_2.RequestBodyRef) *openapi3.RequestBodyRef {
	if body == nil {
		return nil
	}
	return &openapi3.RequestBodyRef{
		Ref:   body.Ref,
		Value: convRequestBody(body.Value),
	}
}

func convRequestBody(value *openapi3_2.RequestBody) *openapi3.RequestBody {
	if value == nil {
		return nil
	}
	n := &openapi3.RequestBody{
		Description: value.Description,
		Required:    value.Required,
		Content:     convMap(value.Content, convMediaType),
	}
	return CopyExtensions(n, value.Extensions)
}

func convParameterRef(v *openapi3_2.ParameterRef) *openapi3.ParameterRef {
	if v == nil {
		return nil
	}
	return &openapi3.ParameterRef{
		Ref:   v.Ref,
		Value: convParameter(v.Value),
	}
}

func convHeaderRef(v *openapi3_2.HeaderRef) *openapi3.HeaderRef {
	if v == nil {
		return nil
	}

	return &openapi3.HeaderRef{
		Ref:   v.Ref,
		Value: convHeader(v.Value),
	}
}

func convHeader(value *openapi3_2.Header) *openapi3.Header {
	if value == nil {
		return nil
	}
	return &openapi3.Header{
		Parameter: *convParameter(&value.Parameter),
	}
}

func convParameter(parameter *openapi3_2.Parameter) *openapi3.Parameter {
	if parameter == nil {
		return nil
	}
	n := &openapi3.Parameter{
		Name:            parameter.Name,
		In:              parameter.In,
		Description:     parameter.Description,
		Style:           parameter.Style,
		Explode:         parameter.Explode,
		AllowEmptyValue: parameter.AllowEmptyValue,
		AllowReserved:   parameter.AllowReserved,
		Deprecated:      parameter.Deprecated,
		Required:        parameter.Required,
		Schema:          convSchemaRef(parameter.Schema),
		Example:         parameter.Example,
		Examples:        convMap(parameter.Examples, convExampleRef),
		Content:         convMap(parameter.Content, convMediaType),
	}
	return CopyExtensions(n, parameter.Extensions)
}

func convMediaType(v *openapi3_2.MediaType) *openapi3.MediaType {
	if v == nil {
		return nil
	}
	return CopyExtensions(&openapi3.MediaType{
		Schema:   convSchemaRef(v.Schema),
		Example:  v.Example,
		Examples: convMap(v.Examples, convExampleRef),
		Encoding: convMap(v.Encoding, convEncoding),
	}, v.Extensions)

}

func convEncoding(encoding *openapi3_2.Encoding) *openapi3.Encoding {
	if encoding == nil {
		return nil
	}
	n := &openapi3.Encoding{
		ContentType:   encoding.ContentType,
		Headers:       convMap(encoding.Headers, convHeaderRef),
		Style:         encoding.Style,
		Explode:       encoding.Explode,
		AllowReserved: encoding.AllowReserved,
	}

	return CopyExtensions(n, encoding.Extensions)
}

func convExampleRef(examples *openapi3_2.ExampleRef) *openapi3.ExampleRef {
	if examples == nil {
		return nil
	}
	n := &openapi3.ExampleRef{
		Ref:   examples.Ref,
		Value: convExample(examples.Value),
	}
	return n
}

func convExample(value *openapi3_2.Example) *openapi3.Example {
	if value == nil {
		return nil
	}
	n := &openapi3.Example{
		Summary:       value.Summary,
		Description:   value.Description,
		Value:         value.Value,
		ExternalValue: value.ExternalValue,
	}
	return CopyExtensions(n, value.Extensions)
}

func convSchemaRef(schema *openapi3_2.SchemaRef) *openapi3.SchemaRef {
	if schema == nil {
		return nil
	}
	n := &openapi3.SchemaRef{
		Ref:   schema.Ref,
		Value: convSchema(schema.Value),
	}
	return n
}

func convSchema(value *openapi3_2.Schema) *openapi3.Schema {
	if value == nil {
		return nil
	}
	n := &openapi3.Schema{
		OneOf:                convArray(value.OneOf, convSchemaRef),
		AnyOf:                convArray(value.AnyOf, convSchemaRef),
		AllOf:                convArray(value.AllOf, convSchemaRef),
		Not:                  convSchemaRef(value.Not),
		Type:                 convTypes(value.Type),
		Title:                value.Title,
		Format:               value.Format,
		Description:          value.Description,
		Enum:                 value.Enum,
		Default:              value.Default,
		Example:              value.Example,
		ExternalDocs:         convExternalDocs(value.ExternalDocs),
		UniqueItems:          value.UniqueItems,
		ExclusiveMin:         value.ExclusiveMin,
		ExclusiveMax:         value.ExclusiveMax,
		Nullable:             value.Nullable,
		ReadOnly:             value.ReadOnly,
		WriteOnly:            value.WriteOnly,
		AllowEmptyValue:      value.AllowEmptyValue,
		Deprecated:           value.Deprecated,
		XML:                  convXml(value.XML),
		Min:                  value.Min,
		Max:                  value.Max,
		MultipleOf:           value.MultipleOf,
		MinLength:            value.MinLength,
		MaxLength:            value.MaxLength,
		Pattern:              value.Pattern,
		MinItems:             value.MinItems,
		MaxItems:             value.MaxItems,
		Items:                convSchemaRef(value.Items),
		Required:             value.Required,
		Properties:           convMap(value.Properties, convSchemaRef),
		MinProps:             value.MinProps,
		MaxProps:             value.MaxProps,
		AdditionalProperties: convAdditionalProperties(value.AdditionalProperties),
		Discriminator:        convDiscriminator(value.Discriminator),
	}
	return CopyExtensions(n, value.Extensions)
}

func convDiscriminator(discriminator *openapi3_2.Discriminator) *openapi3.Discriminator {
	if discriminator == nil {
		return nil
	}
	n := &openapi3.Discriminator{
		PropertyName: discriminator.PropertyName,
		Mapping:      discriminator.Mapping,
	}
	return CopyExtensions(n, discriminator.Extensions)
}

func convAdditionalProperties(properties openapi3_2.AdditionalProperties) openapi3.AdditionalProperties {
	return openapi3.AdditionalProperties{
		Has:    properties.Has,
		Schema: convSchemaRef(properties.Schema),
	}
}

func convXml(xml *openapi3_2.XML) *openapi3.XML {
	if xml == nil {
		return nil
	}
	n := &openapi3.XML{
		Name:      xml.Name,
		Namespace: xml.Namespace,
		Prefix:    xml.Prefix,
		Attribute: xml.Attribute,
		Wrapped:   xml.Wrapped,
	}
	return CopyExtensions(n, xml.Extensions)
}

func convTypes(types *openapi3_2.Types) *openapi3.Types {
	if types == nil {
		return nil
	}
	n := make(openapi3.Types, len(*types))
	copy(n, *types)
	return &n
}
