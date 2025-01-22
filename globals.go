package main

// SecurePayload is the structure we encrypt and store in the QR.
type SecurePayload struct {
	Data   string `json:"data"`   // We'll store the raw JSON in this field
	Expiry int64  `json:"expiry"` // Unix timestamp for code validity
	ID     string `json:"id"`     // Unique ID for one-time usage
}

// usedCodes tracks scanned QR code IDs if we want them to be one-time use.
var usedCodes = make(map[string]bool)

// TransactionInput corresponds to the JSON fields you want to accept.
type TransactionInput struct {
	TransactionID string  `json:"transactionID"`
	BankCode      string  `json:"bankCode" binding:"required"`
	AccountNumber string  `json:"accountNumber" binding:"required"`
	Amount        float64 `json:"amount" binding:"required"`
	Currency      string  `json:"currency"`
	RecipientName string  `json:"recipientName" binding:"required"`
	Purpose       string  `json:"purpose" binding:"required"`
	Expiration    string  `json:"expiration"` // "2024-12-31T23:59:59Z"
	Timestamp     string  `json:"timestamp"`  // "2024-12-16T12:00:00Z"
	Signature     string  `json:"signature"`
	API           string  `json:"api"`
}

type Expiry struct {
	Expiry string `uri:"expiry" binding:"required,min=1"`
}

type ErrorMessage struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type ValidationError struct {
	StatusCode   int            `json:"statusCode"`
	Message      string         `json:"message"`
	ErrorMessage []ErrorMessage `json:"error"`
}
