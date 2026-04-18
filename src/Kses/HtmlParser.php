<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Kses;

use Piplup\Sanitize\Core\Encoding;

/**
 * DOMDocument-based HTML fragment parser for KSES.
 *
 * WHY USE DOMDocument INSTEAD OF REGEX?
 * ─────────────────────────────────────────
 * HTML cannot be reliably parsed with regular expressions.  The structure is
 * recursive (tags nest), context-sensitive (the same bytes mean different
 * things inside a script block vs. a paragraph), and the real-world HTML
 * that attackers submit is often intentionally malformed to exploit regex
 * assumptions.  Classic examples:
 *
 *   <<SCRIPT>alert(1)//<</SCRIPT>       — double-angle trick
 *   <IMG SRC=`javascript:alert(1)`>     — backtick attribute delimiter
 *   <DIV STYLE="background:url(javascript:alert(1))">
 *   <!-- <img src=x onerror=alert(1)> --> — comment bypass
 *
 * DOMDocument uses libxml's HTML parser, the same C library that powers
 * browsers and handles malformed markup in the same way they do.  This makes
 * it far harder to construct an HTML string that the parser sees differently
 * from the browser.
 *
 * RESPONSIBILITIES OF THIS CLASS (SEPARATION OF CONCERNS)
 * ─────────────────────────────────────────────────────────
 * HtmlParser   — parses HTML into a tree, walks the tree, serializes back
 * Kses         — decides which nodes to keep or remove (the policy layer)
 *
 * HtmlParser has NO knowledge of which tags are allowed.  All allow/deny
 * decisions are made in Kses.php.  This separation makes both classes easier
 * to test and reason about in isolation.
 *
 * @internal  Not part of the public API — only Kses.php should use this class.
 */
final class HtmlParser
{
    /**
     * Parse an HTML fragment into a DOMDocument.
     *
     * WHY WE WRAP IN A FULL DOCUMENT STRUCTURE
     * ─────────────────────────────────────────
     * DOMDocument::loadHTML() expects a complete HTML document, not a fragment.
     * Feeding it a bare fragment like "<b>hello</b><p>world</p>" causes libxml
     * to invent surrounding structure (html, head, body) in unpredictable ways.
     *
     * Instead, we construct a minimal but valid HTML5 document that wraps
     * the fragment inside a known container element (<div id="__kses_root__">).
     * After walking the DOM and applying filters, we extract only the inner
     * content of that container — the original fragment, now sanitized.
     *
     * WHY THE CHARSET META TAG?
     * ──────────────────────────
     * Without an explicit charset declaration, libxml assumes Latin-1 (ISO-8859-1)
     * for HTML4.  This causes it to mangle multibyte UTF-8 characters by double-
     * encoding them (e.g. "é" → "Ã©").  The charset meta tag instructs libxml
     * to treat the input as UTF-8.
     *
     * WHY substituteEntities = false?
     * ────────────────────────────────
     * When substituteEntities is true, DOMDocument expands entities like &amp;
     * into their character equivalents during parsing.  This would cause us to
     * serialize "&" where the input had "&amp;", subtly changing the content.
     * Setting it to false preserves entities as-is.
     *
     * @param string $html UTF-8 HTML fragment (may be malformed).
     * @return \DOMDocument Parsed document ready for walking.
     */
    public static function parse(string $html): \DOMDocument
    {
        // Always ensure valid UTF-8 before handing to libxml.
        $html = Encoding::toUtf8($html);

        $doc = new \DOMDocument('1.0', 'UTF-8');

        // Preserve entities during parsing (see docblock explanation).
        $doc->substituteEntities = false;

        // Redirect libxml errors to an internal buffer instead of PHP warnings.
        // Malformed user HTML is expected input, not a programmer error; we do
        // not want to spam logs or output with libxml parse warnings.
        $prev = libxml_use_internal_errors(true);

        // Wrap the fragment in a minimal HTML5 document.
        // The charset meta MUST be inside <head> to take effect.
        // __kses_root__ is our extraction anchor — a stable id we look up later.
        $wrapped = '<!DOCTYPE html><html><head>'
            . '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>'
            . '</head><body><div id="__kses_root__">'
            . $html
            . '</div></body></html>';

        // LIBXML_HTML_NOIMPLIED: don't add implied html/body tags
        // LIBXML_HTML_NODEFDTD:  don't add a default doctype if none is present
        // (Both are best-effort hints; libxml may ignore them for some inputs.)
        $doc->loadHTML($wrapped, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        // Restore the previous error-handling mode and discard any errors that
        // were collected.  We intentionally ignore parse errors — libxml's HTML
        // parser is designed to recover from them, as browsers do.
        libxml_use_internal_errors($prev);
        libxml_clear_errors();

        return $doc;
    }

    /**
     * Serialize the children of the KSES root element back to an HTML string.
     *
     * After Kses::filter() has walked the DOM and removed disallowed nodes,
     * this method extracts only the sanitized content from inside the wrapper
     * div — giving back a fragment, not the full document we constructed.
     *
     * WHY ITERATE CHILD NODES INSTEAD OF USING innerHTML?
     * ─────────────────────────────────────────────────────
     * PHP's DOMDocument has no innerHTML property (unlike the browser DOM).
     * The idiomatic equivalent is to call saveHTML() on each child node and
     * concatenate the results.
     *
     * @param \DOMDocument $doc Previously parsed and filtered document.
     * @return string           The inner HTML of the root container.
     */
    public static function serialize(\DOMDocument $doc): string
    {
        // Locate the wrapper div by its id anchor.
        $root = $doc->getElementById('__kses_root__');

        if ($root === null) {
            // Fallback: some libxml versions do not register ID attributes
            // for HTML documents when using loadHTML().  Try a DOMXPath
            // query to find the element by id as a robust alternative.
            $xpath = new \DOMXPath($doc);
            $nodes = $xpath->query("//*[@id='__kses_root__']");
            if ($nodes !== false && $nodes->length > 0) {
                $root = $nodes->item(0);
            } else {
                return '';
            }
        }

        $html = '';

        // Serialize each direct child of our container.
        // saveHTML($node) serializes that node and its entire subtree.
        foreach ($root->childNodes as $child) {
            $html .= $doc->saveHTML($child);
        }

        return $html;
    }

    /**
     * Walk every DOMElement in the document tree, invoking a callback on each.
     *
     * WHY COLLECT NODES INTO AN ARRAY BEFORE ITERATING?
     * ────────────────────────────────────────────────────
     * The DOMDocument tree is a live structure.  If we iterated using a DOM
     * iterator and the callback removed a node during iteration, the iterator
     * would become invalid and skip or double-visit nodes.
     *
     * By snapshotting all nodes into a flat PHP array first, we decouple the
     * iteration from the tree mutation — the callback can freely modify the
     * tree without affecting the walk.
     *
     * WHY PROCESS DEEPEST NODES FIRST (array_reverse)?
     * ────────────────────────────────────────────────────
     * Consider: <div><b>text</b></div> where both <div> and <b> are disallowed.
     * Kses::filter() replaces a disallowed node with its children.
     *
     * Processing order matters:
     *   DEPTH-FIRST (deepest first, i.e. reversed):
     *     1. Process <b> → replace with "text"       → <div>text</div>
     *     2. Process <div> → replace with "text"     → "text"  ✓ correct
     *
     *   BREADTH-FIRST (shallowest first, i.e. normal):
     *     1. Process <div> → replace with "<b>text</b>"  → "<b>text</b>"
     *     2. Process <b> → it was already moved out of the snapshot's parent
     *        and may be an orphaned node — unpredictable behavior  ✗
     *
    * @param \DOMDocument $doc      Parsed document.
    * @param callable     $callback function(\DOMElement): void — called for each element.
    * @return void
    */
    public static function walk(\DOMDocument $doc, callable $callback): void
    {
        // Phase 1: collect all element nodes into a flat array using recursive
        // iteration. Prefer to traverse only the KSES wrapper root when present
        // to avoid mutating the surrounding <html>/<head>/<body> structure.
        /** @var \DOMElement[] $nodes */
        $nodes = [];

        // Find the wrapper root if it exists.  Some libxml builds do not
        // register id attributes for HTML documents, so fall back to XPath.
        $root = $doc->getElementById('__kses_root__');
        if ($root === null) {
            $xpath = new \DOMXPath($doc);
            $found = $xpath->query("//*[@id='__kses_root__']");
            if ($found !== false && $found->length > 0) {
                $root = $found->item(0);
            }
        }

        $startNode = $root ?? $doc;

        $iterator = new \RecursiveIteratorIterator(
            new RecursiveDomIterator($startNode),
            \RecursiveIteratorIterator::SELF_FIRST  // visit parents before children
        );

        foreach ($iterator as $node) {
            // We only care about element nodes (<b>, <div>, …), not text nodes,
            // comment nodes, or the document root itself.
            if ($node instanceof \DOMElement) {
                $nodes[] = $node;
            }
        }

        // Phase 2: reverse so deepest nodes are processed first.
        // This ensures child nodes are handled before their parents.
        $nodes = array_reverse($nodes);

        // Phase 3: invoke the Kses policy callback on each element.
        foreach ($nodes as $node) {
            $callback($node);
        }
    }
}

// =============================================================================
// Internal helper: RecursiveDomIterator
// =============================================================================

/**
 * Adapter that makes a DOMNode traversable by RecursiveIteratorIterator.
 *
 * WHY THIS CLASS EXISTS
 * ─────────────────────
 * PHP's RecursiveIteratorIterator requires a RecursiveIterator — an interface
 * that provides current(), key(), next(), rewind(), valid(), hasChildren(), and
 * getChildren().  DOMNodeList (the type of $node->childNodes) does not implement
 * RecursiveIterator; it only implements Traversable.
 *
 * This class bridges that gap by wrapping a DOMNode and implementing the
 * RecursiveIterator interface using an integer position cursor over the
 * node's children (snapshotted into a plain array for safety).
 *
 * WHY SNAPSHOT CHILDREN INTO AN ARRAY?
 * ──────────────────────────────────────
 * DOMNodeList is a *live* list — it reflects real-time changes to the DOM.
 * If a child is removed during iteration, the live list shrinks and subsequent
 * index accesses may skip or revisit nodes.  Snapshotting with iterator_to_array()
 * at construction time gives us a stable list that does not change.
 *
 * WHY IS THIS CLASS IN THE Sanitize\Kses NAMESPACE?
 * ───────────────────────────────────────────────────
 * PHP requires that every class in a file with a namespace declaration belongs
 * to that namespace (or a sub-namespace).  Declaring this class after the
 * HtmlParser class but still within the same file means it automatically
 * inherits the file's namespace — Sanitize\Kses.  HtmlParser::walk() therefore
 * references it as just `RecursiveDomIterator` (no leading backslash needed
 * because it resolves within the current namespace).
 *
 * @internal
 */
class RecursiveDomIterator extends \RecursiveArrayIterator
{
    /** The DOMNode whose children we are iterating over. */
    private \DOMNode $node;

    /**
     * Snapshot of $node->childNodes taken at construction time.
     * Stored as a plain PHP array so that DOM mutations during iteration
     * do not invalidate the cursor.
     *
     * @var \DOMNode[]
     */
    private array $children;

    /** Current cursor position within $children. */
    private int $position;

    /**
     * @param \DOMNode $node The node whose children to iterate.
     */
    public function __construct(\DOMNode $node)
    {
        // Call the parent constructor with an empty array because we manage
        // the data source ourselves (via $this->children).
        parent::__construct([]);

        $this->node     = $node;
        // Snapshot the live DOMNodeList into a stable PHP array.
        $this->children = iterator_to_array($node->childNodes);
        $this->position = 0;
    }

    /** Return the current child node. */
    public function current(): \DOMNode
    {
        return $this->children[$this->position];
    }

    /** Return the current integer index (used internally by the iterator). */
    public function key(): int
    {
        return $this->position;
    }

    /** Advance to the next child. */
    public function next(): void
    {
        ++$this->position;
    }

    /** Reset the cursor to the first child. */
    public function rewind(): void
    {
        $this->position = 0;
    }

    /** Return true while there is a child at the current position. */
    public function valid(): bool
    {
        return isset($this->children[$this->position]);
    }

    /**
     * Return true if the current node has children of its own.
     * RecursiveIteratorIterator calls this to decide whether to recurse deeper.
     */
    public function hasChildren(): bool
    {
        return $this->current()->hasChildNodes();
    }

    /**
     * Return a new RecursiveDomIterator for the current node's children.
     * RecursiveIteratorIterator calls this when hasChildren() returns true.
     */
    public function getChildren(): self
    {
        return new self($this->current());
    }
}
