package simba

const (
	STATUS_MORE_PROCESSING_REQUIRED uint32 = 0xC0000016
	STATUS_LOGON_FAILURE            uint32 = 0xC000006D

	// Add these additional status codes
	STATUS_SUCCESS           uint32 = 0x00000000
	STATUS_ACCESS_DENIED     uint32 = 0xC0000022
	STATUS_INVALID_PARAMETER uint32 = 0xC000000D
)
