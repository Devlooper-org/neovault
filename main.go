package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/jigarvarma2k20/neovault/database"
	"github.com/jigarvarma2k20/neovault/handlers"
	"github.com/jigarvarma2k20/neovault/middlewares"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/gofiber/template/html/v3"
	"github.com/joho/godotenv"
)

//go:embed views public
var embedFS embed.FS

func main() {
	godotenv.Load()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET is required")
	}

	database.ConnectDB(dsn)

	// Embedded views
	viewsFS, _ := fs.Sub(embedFS, "views")
	engine := html.NewFileSystem(http.FS(viewsFS), ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Embedded static files
	cssFS, _ := fs.Sub(embedFS, "public/css")
	app.Get("/css/*", static.New("", static.Config{
		FS: cssFS,
	}))

	// Routes
	app.Get("/", func(c fiber.Ctx) error { return c.Redirect().To("/login") })
	app.Get("/login", handlers.ShowLogin)
	app.Post("/login", handlers.Login)
	app.Get("/register", handlers.ShowRegister)
	app.Post("/register", handlers.Register)
	app.Get("/logout", handlers.Logout)

	// TOTP
	app.Get("/totp/setup", handlers.ShowTOTPSetup)
	app.Post("/totp/verify", handlers.VerifyTOTPSetup)
	app.Post("/totp/skip", handlers.SkipTOTP)
	app.Get("/totp/login", handlers.ShowTOTPLogin)
	app.Post("/totp/login", handlers.VerifyTOTPLogin)

	// Protected routes (require valid auth_token JWT)
	protected := app.Group("", middlewares.Auth)

	protected.Get("/dashboard", handlers.ShowDashboard)

	// Vault
	protected.Get("/vault/setup", handlers.ShowVaultSetup)
	protected.Post("/vault/setup", handlers.SetupVault)
	protected.Get("/vault/unlock", handlers.ShowVaultUnlock)
	protected.Post("/vault/unlock", handlers.UnlockVault)
	protected.Post("/vault/add", handlers.AddPassword)
	protected.Post("/vault/decrypt/:id", handlers.DecryptPassword)
	protected.Post("/vault/delete/:id", handlers.DeletePassword)

	// Settings
	protected.Post("/settings/change-password", handlers.ChangePassword)

	log.Fatal(app.Listen(":3000"))
}
