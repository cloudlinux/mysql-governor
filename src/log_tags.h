/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 */

// severities:
DEFINE_LOG_TAG(ERR)			// ALWAYS ENABLED
DEFINE_LOG_TAG(INFO)		// informational
DEFINE_LOG_TAG(IMPORTANT)	// informational, but ALWAYS ENABLED
// facilities:
DEFINE_LOG_TAG(LIFE)		// overall lifecycle - start, stop, creation and termination of main threads; ALWAYS ENABLED
DEFINE_LOG_TAG(SLOW)		// slow queries
DEFINE_LOG_TAG(DBTOP)		// dbtop and dbctl communication
DEFINE_LOG_TAG(USRMAP)		// user map
DEFINE_LOG_TAG(USRMAPRQ)	// user map on request
DEFINE_LOG_TAG(MON)			// resource monitor
DEFINE_LOG_TAG(SRV)			// systemd service
DEFINE_LOG_TAG(DMN)			// daemon
DEFINE_LOG_TAG(LVE)			// LVE immediate operations and thread state
// activities:
DEFINE_LOG_TAG(FRZ)			// freeze
DEFINE_LOG_TAG(UNFRZ)		// unfreeze
DEFINE_LOG_TAG(MYSQL)		// MySQL connector
