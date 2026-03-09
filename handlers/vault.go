package handlers

import (
	"github.com/jigarvarma2k20/neovault/models"
	"github.com/jigarvarma2k20/neovault/repository"
	"github.com/jigarvarma2k20/neovault/utils"

	"github.com/gofiber/fiber/v3"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func ShowVaultSetup(c fiber.Ctx) error {
	return c.Render("vault/setup", fiber.Map{
		"Title": "Setup Vault - NeoVault",
	}, "layout")
}

// SetupVault hashes the master password and registers the vault session.
func SetupVault(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	parentPassword := c.FormValue("parent_password")
	parentPasswordConfirm := c.FormValue("parent_password_confirm")

	if parentPassword == "" || parentPassword != parentPasswordConfirm {
		return c.Status(400).JSON(fiber.Map{"error": "Passwords do not match or are empty"})
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(parentPassword), 12)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Internal error"})
	}

	user, err := repository.GetUserByID(userID)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	user.ParentPasswordHash = string(hash)
	repository.UpdateUser(user)

	// session token only; master password stays on client
	vaultToken, _ := utils.GenerateVaultToken(userID)
	c.Cookie(&fiber.Cookie{
		Name:     "vault_token",
		Value:    vaultToken,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
	})

	return c.JSON(fiber.Map{"ok": true})
}

func ShowVaultUnlock(c fiber.Ctx) error {
	return c.Render("vault/unlock", fiber.Map{
		"Title": "Unlock Vault - NeoVault",
	}, "layout")
}

// UnlockVault validates the provided master password.
func UnlockVault(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	parentPassword := c.FormValue("parent_password")

	user, err := repository.GetUserByID(userID)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.ParentPasswordHash), []byte(parentPassword)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid Master Password"})
	}

	vaultToken, _ := utils.GenerateVaultToken(userID)
	c.Cookie(&fiber.Cookie{
		Name:     "vault_token",
		Value:    vaultToken,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
	})

	return c.JSON(fiber.Map{"ok": true})
}

// ShowDashboard renders the primary vault view
func ShowDashboard(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	user, err := repository.GetUserByID(userID)
	if err != nil {
		return c.Redirect().To("/login")
	}

	if user.ParentPasswordHash == "" {
		return c.Redirect().To("/vault/setup")
	}

	vaultToken := c.Cookies("vault_token")
	if vaultToken == "" {
		return c.Redirect().To("/vault/unlock")
	}
	if _, err = utils.VerifyVaultToken(vaultToken); err != nil {
		return c.Redirect().To("/vault/unlock")
	}

	entries, _ := repository.GetPasswordEntriesByUserID(userID)

	return c.Render("dashboard/index", fiber.Map{
		"Title":   "Vault - NeoVault",
		"Entries": entries,
	}, "layout")
}

// AddPassword stores a new client-side encrypted credential.
func AddPassword(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	website := c.FormValue("website")
	username := c.FormValue("username")
	encryptedPassword := c.FormValue("encrypted_password") // AES-GCM ciphertext from client
	totpSecret := c.FormValue("totp_secret")
	totpCode := c.FormValue("totp_code")

	if website == "" || username == "" || encryptedPassword == "" {
		return c.Status(400).SendString("Website, username, and encrypted_password are required")
	}

	// Verify vault is unlocked (session check only)
	vaultToken := c.Cookies("vault_token")
	if _, err := utils.VerifyVaultToken(vaultToken); err != nil {
		return c.Status(401).JSON(fiber.Map{"vault_locked": true, "error": "Vault is locked"})
	}

	// Only verify TOTP if the user configured 2FA for this credential
	if totpSecret != "" && totpCode != "" {
		if !totp.Validate(totpCode, totpSecret) {
			return c.Status(401).SendString("Invalid TOTP code")
		}
	}

	entry := models.PasswordEntry{
		UserID:            userID,
		Website:           website,
		WebsiteUsername:   username,
		EncryptedPassword: encryptedPassword, // stored as-is; only client can decrypt
		TOTPSecret:        totpSecret,
	}
	if err := repository.CreatePasswordEntry(&entry); err != nil {
		return c.Status(500).SendString("Error saving credential")
	}

	return c.Redirect().To("/dashboard")
}

// DecryptPassword returns the stored ciphertext for client-side decryption.
func DecryptPassword(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	entryID := c.Params("id")

	totpCode := c.FormValue("totp_code")

	// Vault session check
	vaultToken := c.Cookies("vault_token")
	if _, err := utils.VerifyVaultToken(vaultToken); err != nil {
		return c.Status(401).JSON(fiber.Map{"vault_locked": true, "error": "Vault is locked"})
	}

	entry, err := repository.GetPasswordEntryByIDAndUserID(entryID, userID)
	if err != nil {
		return c.Status(404).SendString("Credential not found")
	}

	// Only verify TOTP if the credential has 2FA configured
	if entry.TOTPSecret != "" {
		if totpCode == "" {
			return c.Status(400).SendString("This credential requires a TOTP code")
		}
		if !totp.Validate(totpCode, entry.TOTPSecret) {
			return c.Status(401).SendString("Invalid TOTP code for this credential")
		}
	}

	// return ciphertext for client-side decryption
	return c.JSON(fiber.Map{
		"ciphertext": entry.EncryptedPassword,
		"website":    entry.Website,
	})
}

// DeletePassword deletes a credential after TOTP verification
func DeletePassword(c fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	entryID := c.Params("id")

	totpCode := c.FormValue("totp_code")

	vaultToken := c.Cookies("vault_token")
	if _, err := utils.VerifyVaultToken(vaultToken); err != nil {
		return c.Status(401).JSON(fiber.Map{"vault_locked": true, "error": "Vault is locked. Please unlock your vault first."})
	}

	entry, err := repository.GetPasswordEntryByIDAndUserID(entryID, userID)
	if err != nil {
		return c.Status(404).SendString("Credential not found")
	}

	// Only verify TOTP if this credential has 2FA configured
	if entry.TOTPSecret != "" {
		if totpCode == "" {
			return c.Status(400).SendString("This credential requires a TOTP code to delete")
		}
		if !totp.Validate(totpCode, entry.TOTPSecret) {
			return c.Status(401).SendString("Invalid TOTP code for this credential")
		}
	}

	if err := repository.DeletePasswordEntry(entryID, userID); err != nil {
		return c.Status(500).SendString("Failed to delete credential")
	}

	return c.SendString("ok")
}
