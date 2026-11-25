// Commande aplomb : point d'entrée de la ligne de commande.
//
// Étape 0 : seules les commandes hello, version et help existent. Sans
// argument, aplomb lancera l'audit (étape 3) ; en attendant, il affiche hello.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/maxb1906/aplomb/internal/i18n"
)

// version est injectée à la compilation : -ldflags "-X main.version=v0.1.0".
var version = "dev"

// env regroupe ce dont une commande a besoin.
type env struct {
	ctx    context.Context
	bundle *i18n.Bundle
	tr     *i18n.Translator
	stdout io.Writer
	stderr io.Writer
}

func (e *env) T(key string, pairs ...string) string { return e.tr.T(key, pairs...) }

type command struct {
	run func(e *env, args []string) int
}

var commands = map[string]command{}

// order fixe l'ordre d'affichage des commandes dans l'aide.
var order = []string{"hello", "version", "help"}

// defaultCommand est lancée sans argument (double-clic sur l'exe).
const defaultCommand = "hello"

func init() {
	commands["hello"] = command{run: cmdHello}
	commands["version"] = command{run: func(e *env, _ []string) int { fmt.Fprintln(e.stdout, version); return 0 }}
	commands["help"] = command{run: func(e *env, _ []string) int { usage(e, e.stdout); return 0 }}
}

func usage(e *env, w io.Writer) {
	fmt.Fprintln(w, e.T("cli.usage"))
	fmt.Fprintln(w, e.T("cli.commands"))
	for _, c := range order {
		fmt.Fprintf(w, "  %-12s %s\n", c, e.T("cmd."+c))
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := func() (code int) {
		// Lancé par double-clic, la console se ferme à la sortie : on garde
		// le résultat (ou le plantage) visible jusqu'à ce que l'utilisateur valide.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "panic: %v\n%s\n", r, debug.Stack())
				code = 3
			}
			if launchedAlone() {
				pause(os.Args[1:])
			}
		}()
		return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	}()
	stop()
	os.Exit(code)
}

// pause affiche « Appuyez sur Entrée » et attend.
func pause(args []string) {
	msg := "Appuyez sur Entrée pour fermer cette fenêtre. / Press Enter to close this window."
	if b, err := i18n.Default(); err == nil {
		lang := b.Detect()
		for i, a := range args {
			if a == "--lang" && i+1 < len(args) && b.Has(args[i+1]) {
				lang = args[i+1]
			}
		}
		msg = b.Translator(lang).T("cli.press_enter")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, msg)
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	bundle, err := i18n.Default()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	e := &env{ctx: ctx, bundle: bundle, stdout: stdout, stderr: stderr}
	e.tr = bundle.Translator(bundle.Detect())

	fs := flag.NewFlagSet("aplomb", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	lang := fs.String("lang", "", "fr|en")
	parseErr := fs.Parse(args)

	if *lang != "" {
		if !bundle.Has(*lang) {
			fmt.Fprintln(stderr, e.T("cli.unknown_lang", "lang", *lang, "available", strings.Join(bundle.Languages(), ", ")))
			return 2
		}
		e.tr = bundle.Translator(*lang)
	}

	if parseErr == flag.ErrHelp {
		usage(e, stdout)
		return 0
	}
	if parseErr != nil {
		fmt.Fprintln(stderr, e.T("cli.error", "error", parseErr.Error()))
		usage(e, stderr)
		return 2
	}

	name, rest := defaultCommand, []string(nil)
	if fs.NArg() > 0 {
		name, rest = fs.Arg(0), fs.Args()[1:]
	}
	c, ok := commands[name]
	if !ok {
		fmt.Fprintln(stderr, e.T("cli.unknown_command", "command", name))
		usage(e, stderr)
		return 2
	}
	return c.run(e, rest)
}
