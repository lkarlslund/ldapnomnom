package main

import (
	"github.com/lkarlslund/ldap/v3"
)

var defaultDumpAttrs = []string{
	"configurationNamingContext",
	"currentTime",
	"defaultNamingContext",
	"dNSHostName",
	"dsSchemaAttrCount",
	"dsSchemaClassCount",
	"dsSchemaPrefixCount",
	"dsServiceName",
	"highestCommittedUSN",
	"isGlobalCatalogReady",
	"isSynchronized",
	"ldapServiceName",
	"namingContexts",
	"netlogon",
	"pendingPropagations",
	"rootDomainNamingContext",
	"schemaNamingContext",
	"serverName",
	"subschemaSubentry",
	"supportedCapabilities",
	"supportedControl",
	"supportedLDAPPolicies",
	"supportedLDAPVersion",
	"supportedSASLMechanisms",
	"domainControllerFunctionality",
	"domainFunctionality",
	"forestFunctionality",
	"msDS-ReplAllInboundNeighbors",
	"msDS-ReplAllOutboundNeighbors",
	"msDS-ReplConnectionFailures",
	"msDS-ReplLinkFailures",
	"msDS-ReplPendingOps",
	"msDS-ReplQueueStatistics",
	"msDS-TopQuotaUsage",
	"supportedConfigurableSettings",
	"supportedExtension",
	"validFSMOs",
	"dsaVersionString",
	"msDS-PortLDAP",
	"msDS-PortSSL",
	"msDS-PrincipalName",
	"serviceAccountInfo",
	"spnRegistrationResult",
	"tokenGroups",
	"usnAtRifm",
	"approximateHighestInternalObjectID",
	"databaseGuid",
	"schemaIndexUpdateState",
	"dumpLdapNotifications",
	"msDS-ProcessLinksOperations",
	"msDS-SegmentCacheInfo",
	"msDS-ThreadStates",
	"ConfigurableSettingsEffective",
	"LDAPPoliciesEffective",
	"msDS-ArenaInfo",
	"msDS-Anchor",
	"msDS-PrefixTable",
	"msDS-SupportedRootDSEAttributes",
	"msDS-SupportedRootDSEModifications",
}

func dumpRootDSE(conn *ldap.Conn) (map[string][]string, error) {
	result := make(map[string][]string)

	// See if we can ask the server what attributes it knows about
	probeAttrs := getRootDSEAttribute(conn, "msDS-SupportedRootDSEAttributes")
	if len(probeAttrs) == 0 {
		probeAttrs = defaultDumpAttrs
	}

	// Extract what we can
	for _, attribute := range probeAttrs {
		result[attribute] = getRootDSEAttribute(conn, attribute)
	}
	return result, nil
}

func getRootDSEAttribute(conn *ldap.Conn, attribute string) []string {
	request := ldap.NewSearchRequest(
		"", // The base dn to search
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",   // The filter to apply
		[]string{attribute}, // A list attributes to retrieve
		nil,
	)
	response, err := conn.Search(request)
	if err == nil && len(response.Entries) == 1 && len(response.Entries[0].Attributes) == 1 {
		return response.Entries[0].Attributes[0].Values
	}
	return nil
}
