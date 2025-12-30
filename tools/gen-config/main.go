//nolint:forbidigo,errcheck
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

const (
	docsFileDest = ""
)

type structDef struct {
	Name        string
	DisplayName string
	StructType  *ast.StructType
}

var structTypes map[string]structDef

func generateFromStruct(dir string) error {
	outYAML, err := os.Create("config.sample.yaml")
	if err != nil {
		return err
	}
	defer outYAML.Close()

	outFileMD, err := os.Create("config.md")
	if err != nil {
		return err
	}
	defer outFileMD.Close()

	outBufMD := &bytes.Buffer{}
	outMD := io.MultiWriter(outBufMD, outFileMD)

	// Map to store struct types defined in the file
	structTypes = make(map[string]structDef)

	// Collect all struct types in the main config.go file
	err = parseStructsInFile(filepath.Join(dir, "config.go"))
	if err != nil {
		return fmt.Errorf("failed to parse structs in config.go file: %w", err)
	}

	// Process the root Config struct
	processStruct(structTypes["Config"], "", "", "", outYAML, outMD, false)

	if docsFileDest != "" {
		// Replace the configuration table in the docs file file
		readme, err := os.ReadFile(filepath.Join(".", docsFileDest))
		if err != nil {
			return err
		}

		const (
			beginMarker = "<!-- BEGIN CONFIG TABLE -->"
			endMarker   = "<!-- END CONFIG TABLE -->"
		)
		begin := bytes.Index(readme, []byte(beginMarker)) + len(beginMarker)
		end := bytes.Index(readme, []byte(endMarker))

		readmeFile, err := os.Create(filepath.Join(".", docsFileDest))
		if err != nil {
			return err
		}
		defer readmeFile.Close()
		readmeFile.Write(readme[:begin])
		readmeFile.Write([]byte{'\n'})
		io.Copy(readmeFile, outBufMD)
		readmeFile.Write([]byte{'\n'})
		readmeFile.Write(readme[end:])
	}

	return nil
}

func parseStructsInFile(fileName string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, fileName, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	// Collect all struct types in the file
	ast.Inspect(node, func(n ast.Node) bool {
		x, ok := n.(*ast.GenDecl)
		if !ok {
			return true
		}

		if len(x.Specs) == 0 {
			return true
		}

		typeSpec, ok := x.Specs[0].(*ast.TypeSpec)
		if !ok {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		def := structDef{
			StructType: structType,
		}
		for _, line := range strings.Split(x.Doc.Text(), "\n") {
			switch {
			case strings.HasPrefix(line, "+name "):
				def.Name = strings.TrimPrefix(line, "+name ")
			case strings.HasPrefix(line, "+displayName "):
				def.DisplayName = strings.TrimPrefix(line, "+displayName ")
			}
		}

		structTypes[typeSpec.Name.Name] = def

		return true
	})

	return nil
}

// processStruct processes a struct type recursively, generating documentation for each field
func processStruct(structDef structDef, yamlPrefix string, parentYamlPath string, sectionName string, outYAML io.Writer, outMD io.Writer, skipComments bool) {
	y := func(format string, a ...any) { fmt.Fprintf(outYAML, yamlPrefix+format, a...) }

	providerName := ""
	switch {
	case parentYamlPath == "" && sectionName == "":
		printMarkdownHeader("## Root configuration object", outMD)
	}

	for _, field := range structDef.StructType.Fields.List {
		// Skip fields without tags
		if field.Tag == nil {
			continue
		}

		unquoted, _ := strconv.Unquote(field.Tag.Value)
		tags := reflect.StructTag(unquoted)
		yamlTag, ok := tags.Lookup("yaml")
		if !ok || yamlTag == "" || yamlTag == "-" {
			continue
		}

		// Skip deprecated or ignored fields
		deprecatedTag, _ := tags.Lookup("deprecated")
		deprecated, _ := strconv.ParseBool(deprecatedTag)
		if deprecated {
			continue
		}
		ignoreTag, _ := tags.Lookup("ignoredocs")
		ignore, _ := strconv.ParseBool(ignoreTag)
		if ignore {
			continue
		}

		// Check if there's an "omitempty" suffix
		yamlTag, hasOmitEmpty := strings.CutSuffix(yamlTag, ",omitempty")
		_ = hasOmitEmpty

		// Build the full YAML path
		fullYamlPath := yamlTag
		if parentYamlPath != "" {
			fullYamlPath = parentYamlPath + "." + yamlTag
		}

		// Check if this field is a struct
		isStructField := false
		var structName string
		ident, ok := field.Type.(*ast.Ident)
		if ok {
			structName = ident.Name
			_, isStructField = structTypes[structName]
		}

		// Check if it's a pointer to a struct
		starExp, ok := field.Type.(*ast.StarExpr)
		if ok {
			ident, ok = starExp.X.(*ast.Ident)
			if ok {
				structName = ident.Name
				_, isStructField = structTypes[structName]
			}
		}

		switch {
		// Handle regular (non-struct) fields
		case !isStructField:
			processField(field, fullYamlPath, sectionName, outYAML, outMD, yamlPrefix, skipComments)

		// Process nested struct
		case isStructField:
			nestedStruct := structTypes[structName]
			if providerName != "" && nestedStruct.Name != providerName {
				// One provider per block
				continue
			}
			if nestedStruct.StructType != nil {
				// Only output a header for this struct if it's not the root
				if parentYamlPath != "" {
					if !skipComments {
						y("## %s\n", fullYamlPath)
						if field.Doc != nil && field.Doc.Text() != "" {
							y("## Description:\n")
							for _, line := range strings.Split(field.Doc.Text(), "\n") {
								if line != "" {
									y("##   %s\n", line)
								}
							}
						}
					}
					// Generate proper YAML indentation for nested structures
					y("%s:\n", yamlTag)
				} else {
					// For top-level fields
					y("%s:\n", yamlTag)
				}

				// Process nested fields with appropriate indentation
				processStruct(nestedStruct, yamlPrefix+"  ", fullYamlPath, sectionName, outYAML, outMD, skipComments)
			}
		}
	}
}

// processField handles a single field, generating documentation
func processField(field *ast.Field, yamlTag string, sectionName string, outYAML io.Writer, outMD io.Writer, yamlPrefix string, skipComments bool) {
	var (
		defaultText, doc, example, value string
		required, recommended, lastEmpty bool
	)

	y := func(format string, a ...any) { fmt.Fprintf(outYAML, yamlPrefix+format, a...) }

	// Get the last part of the YAML path for field name (after the last dot)
	fieldName := yamlTag
	if idx := strings.LastIndex(yamlTag, "."); idx > -1 {
		fieldName = yamlTag[idx+1:]
	}

	// Field type
	typ := fieldTypeName(field)

	anchor := strings.ReplaceAll(yamlTag, ".", "-")
	if sectionName != "" {
		anchor = sectionName + "-" + anchor
	}

	// Parse field documentation
	if !skipComments {
		y("## %s (%s)\n", yamlTag, typ)
	}
	fmt.Fprintf(outMD, "| <a id=\"config-opt-%s\"></a>`%s` | %s | ", strings.ToLower(anchor), yamlTag, typ)
	if field.Doc != nil {
		doc = field.Doc.Text()
	}
	var mdFooter string
	if doc != "" {
		if !skipComments {
			y("## Description:\n")
		}
		for i, line := range strings.Split(doc, "\n") {
			if line == "" {
				lastEmpty = true
				continue
			}

			switch {
			case strings.HasPrefix(line, "+default "):
				defaultText = strings.TrimPrefix(line, "+default ")
			case strings.TrimSpace(line) == "+required":
				required = true
			case strings.TrimSpace(line) == "+recommended":
				recommended = true
			case strings.HasPrefix(line, "+example "):
				example = strings.TrimPrefix(line, "+example ")
			default:
				if !skipComments {
					if lastEmpty {
						y("##\n")
						fmt.Fprint(outMD, "<br>")
					}
					y("##   %s\n", line)
					if i > 0 {
						fmt.Fprint(outMD, "<br>"+line)
					} else {
						fmt.Fprint(outMD, line)
					}
					lastEmpty = false
				}
			}
		}

		if defaultText != "" {
			y("## Default: %s\n", defaultText)
			mdFooter = "Default: _" + defaultText + "_"
		}
	}

	// Get the value to show
	value = defaultText
	if value == "" {
		if example != "" {
			value = example
		} else {
			value = defaultValueForType(field.Type)
		}
	}

	if required {
		if !skipComments {
			y("## Required\n")
			y("%s: %s\n\n", fieldName, value)
		} else {
			y("%s: %s\n", fieldName, value)
		}
		mdFooter = "**Required**"
	} else {
		if recommended {
			if mdFooter != "" {
				mdFooter = "Recommended<br>" + mdFooter
			} else {
				mdFooter = "Recommended"
			}
		}
		if !skipComments {
			y("#%s: %s\n\n", fieldName, value)
		} else {
			y("#%s: %s\n", fieldName, value)
		}
	}
	fmt.Fprintf(outMD, "| %s |\n", mdFooter)
}

func printMarkdownHeader(header string, outMD io.Writer) {
	fmt.Fprintf(outMD, "%s\n\n", header)
	fmt.Fprint(outMD, "| Name | Type | Description | |\n")
	fmt.Fprint(outMD, "| --- | --- | --- | --- |\n")
}

// fieldTypeName returns a human-readable name for a field type
func fieldTypeName(field *ast.Field) string {
	ft := types.ExprString(field.Type)
	switch ft {
	case "string":
		return "string"
	case "int":
		return "number"
	case "bool":
		return "boolean"
	case "time.Duration":
		return "duration"
	case "[]string":
		return "list of strings"
	case "float64", "float32":
		return "float"
	default:
		switch {
		case strings.HasPrefix(ft, "[]"):
			return "list"
		case strings.HasPrefix(ft, "map["):
			return "map"
		default:
			return ft
		}
	}
}

// defaultValueForType returns a simple example for a type (string placeholders)
func defaultValueForType(expr ast.Expr) string {
	ft := types.ExprString(expr)
	switch ft {
	case "string":
		return `""`
	case "int":
		return "0"
	case "bool":
		return "false"
	case "time.Duration":
		return "0s"
	case "[]string":
		return "[]"
	default:
		return "" // unknown or nested
	}
}

func main() {
	err := generateFromStruct(filepath.Join("pkg", "config"))
	if err != nil {
		panic(err)
	}
}
