package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"os"
	"strings"
	"time"
)

var passphrase, salt string
var encKey, macKey []byte

func init() {
	passphrase = os.Getenv("QR_APP_PASSPHRASE")
	if passphrase == "" {
		// For demo fallback
		passphrase = "mysecretkey123456"
	}

	// -------------------------- Setup Salt ----------------------------------
	salt = "my-stable-salt"

	// ------------------------ Derive Master Key -----------------------------
	masterKey := deriveMasterKey(passphrase, salt)
	encKey, macKey = splitKey(masterKey)
}

func main() {
	r := gin.Default()
	r.Use(CORSMiddleware())
	//r.POST("/generate/:expiry", func(c *gin.Context) {
	r.POST("/generate", func(c *gin.Context) {
		var tx TransactionInput
		//var expiryMin Expiry
		if err := c.ShouldBind(&tx); err != nil {
			err = ValidateRequest(err)
			fmt.Println(err)
			_ = c.Error(err)
			return
		}
		//if err := c.ShouldBindUri(&expiryMin); err != nil {
		//	err = ValidateRequest(err)
		//	fmt.Println(err)
		//	_ = c.Error(err)
		//	return
		//}
		expiry := time.Now().Add(time.Duration(5) * time.Minute).Unix()
		transaction := TransactionInput{
			TransactionID: uuid.New().String(),
			BankCode:      tx.BankCode,
			AccountNumber: tx.AccountNumber,
			Amount:        tx.Amount,
			Currency:      "NGN",
			RecipientName: tx.RecipientName,
			Purpose:       tx.Purpose,
			Expiration:    time.Unix(expiry, 0).UTC().Format(time.RFC3339),
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			Signature:     GenerateSecureRandomString(),
			API:           "/v1/transactions/pay",
		}
		payloadBytes, err := json.Marshal(transaction)
		if err != nil {
			c.JSON(400, gin.H{"msg": "Failed to marshal TransactionInput"})
			return
		}
		plaintext := string(payloadBytes)
		//i, err := strconv.Atoi(expiryMin.Expiry)
		//if err != nil {
		//	c.JSON(400, gin.H{"msg": "Invalid expiry time"})
		//	return
		//}

		codeID := fmt.Sprintf("qr_%d", randomInt(1000000000))

		// 5. Create the SecurePayload
		payloadStruct := SecurePayload{
			Data:   plaintext,
			Expiry: expiry,
			ID:     codeID,
		}

		// 6. Marshal and encrypt
		securePayloadBytes, err := json.Marshal(payloadStruct)
		if err != nil {
			c.JSON(400, gin.H{"msg": "Failed to marshal payload"})
			return
		}
		encryptedData, err := encrypt(string(securePayloadBytes), encKey)
		if err != nil {
			c.JSON(400, gin.H{"msg": "Encryption failed"})
			return
		}

		// 7. Sign
		signature := sign(encryptedData, macKey)
		combined := encryptedData + ":" + signature

		c.JSON(200, gin.H{
			"data": combined,
		})
	}, ErrorHandlerMiddleware())
	r.POST("/scan", func(c *gin.Context) {
		var data struct {
			Combined string `json:"combined" binding:"required"`
		}
		if err := c.ShouldBind(&data); err != nil {
			err = ValidateRequest(err)
			fmt.Println(err)
			_ = c.Error(err)
			return
		}
		// 2. Decode from file
		combined := data.Combined
		var err error

		// 3. Split encrypted data from signature
		parts := strings.SplitN(combined, ":", 2)
		if len(parts) != 2 {
			c.JSON(400, gin.H{"msg": "Invalid payload format"})
			return
		}
		encryptedData, sig := parts[0], parts[1]

		// 4. Validate signature
		if !validateSignature(encryptedData, sig, macKey) {
			c.JSON(400, gin.H{"msg": "Invalid signature. Data might be tampered with"})
			return
		}

		// 5. Decrypt
		decryptedJSON, err := decrypt(encryptedData, encKey)
		if err != nil {
			c.JSON(400, gin.H{"msg": "Decryption failed"})
			return
		}

		// 6. Unmarshal the SecurePayload
		var payloadStruct SecurePayload
		if err = json.Unmarshal([]byte(decryptedJSON), &payloadStruct); err != nil {
			c.JSON(400, gin.H{"msg": "Failed to unmarshal JSON payload"})
			return
		}

		// 7. Check if this code is already used
		if usedCodes[payloadStruct.ID] {
			c.JSON(400, gin.H{"msg": "This QR code has already been used"})
			return
		}

		// 8. Check TTL / expiry
		nowUnix := time.Now().Unix()
		if nowUnix > payloadStruct.Expiry {
			c.JSON(400, gin.H{"msg": "QR code has expired"})
			return
		}

		// 9. Mark the code as used
		usedCodes[payloadStruct.ID] = true

		// Now you can parse the embedded JSON data for actual usage.
		// The `payloadStruct.Data` field is a JSON string of `TransactionInput`.
		var transaction TransactionInput
		if err = json.Unmarshal([]byte(payloadStruct.Data), &transaction); err != nil {
			c.JSON(400, gin.H{"msg": "Failed to unmarshal transaction data"})
			return
		}

		c.JSON(200, gin.H{
			"transaction": transaction,
		})

	}, ErrorHandlerMiddleware())
	r.Run(":9000") // listen and serve on 0.0.0.0:8080
}
