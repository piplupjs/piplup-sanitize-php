<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Kses;

/**
 * Pre-defined allowed-HTML presets for the KSES filter.
 *
 * HOW THE ALLOW-LIST FORMAT WORKS
 * ─────────────────────────────────
 * Each preset returns a nested associative array in this shape:
 *
 *   [
 *     'tagname' => [
 *       'attribute-name' => true,   // attribute is allowed; any value permitted
 *       'href'           => true,   // URL attributes are additionally validated
 *     ],
 *     'br' => [],                   // empty array = tag allowed, no attributes
 *   ]
 *
 * Tag and attribute names are matched case-insensitively by Kses::filter().
 *
 * WHICH PRESET SHOULD I USE?
 * ───────────────────────────
 * • post()   — full rich-text editing: headings, links, images, tables, …
 *              Use for: blog post bodies, article content, comment text
 *
 * • data()   — minimal inline emphasis only: <a>, <b>, <em>, <code>, …
 *              Use for: user bios, short descriptions, tooltip text
 *
 * • inline() — inline only, zero block-level elements
 *              Use for: meta descriptions, search result snippets, labels
 *
 * WHY NOT ALLOW <script>, <iframe>, <object>, <embed>?
 * ──────────────────────────────────────────────────────
 * These elements execute code or load arbitrary external content and have no
 * safe subset of attribute values.  They are intentionally absent from all
 * presets.  If you genuinely need to embed third-party content, do so server-
 * side (store the URL, render the embed yourself) rather than allowing users
 * to inject arbitrary embed code.
 *
 * WHY IS <form> NOT INCLUDED?
 * ────────────────────────────
 * Forms in user-generated content allow CSRF attacks and can submit data to
 * arbitrary servers.  The action attribute alone is enough to exfiltrate data.
 *
 * HOW TO CREATE A CUSTOM ALLOW-LIST
 * ────────────────────────────────────
 * Start from one of these presets and add or remove entries:
 *
 *   $allowed = AllowedHtml::data();
 *   $allowed['mark'] = [];                          // add <mark>
 *   $allowed['a']['download'] = true;              // allow download attr on <a>
 *   unset($allowed['q']);                           // remove <q>
 *   $clean = Kses::filter($html, $allowed);
 */
final class AllowedHtml
{
    /**
     * Full rich-text / "post content" preset.
     *
     * Suitable for any user-supplied body text that should support full prose
     * formatting including headings, links, images, and tables.
     *
     * NOTABLE INCLUSIONS AND WHY:
     *   <a>   — with href, target, rel.  href values are run through
     *           UrlSanitizer::escUrlRaw() by Kses to block javascript: URIs.
     *   <img> — with src, alt, width, height.  src is validated by UrlSanitizer.
     *           Note: no srcset or sizes — those require additional validation.
     *   <table> family — useful for data tables in articles.
     *   style attribute on div/p/span — allows basic inline styling.
     *           WARNING: if you want to prevent style injection (e.g. CSS
     *           that hides content, creates overlays, or loads external URLs)
     *           you may want to remove 'style' from this preset and handle CSS
     *           separately.
     *
     * Equivalent to the allow-list used by WordPress wp_kses_post().
     *
     * @return array<string, array<string, bool>>
     */
    public static function post(): array
    {
        return [
            // ── Inline text formatting ──────────────────────────────────────
            'a'          => ['href' => true, 'title' => true, 'target' => true, 'rel' => true, 'class' => true, 'id' => true],
            'abbr'       => ['title' => true],          // abbreviation with tooltip
            'acronym'    => ['title' => true],          // legacy (HTML4), kept for compatibility
            'b'          => [],                          // bold (presentational)
            'cite'       => [],                          // citation
            'code'       => ['class' => true],          // inline code (class for syntax highlighters)
            'del'        => ['datetime' => true],        // deleted text with optional timestamp
            'dfn'        => [],                          // definition term
            'em'         => [],                          // emphasis (semantic italic)
            'i'          => ['class' => true],          // italic (presentational; class for icon fonts)
            'ins'        => ['datetime' => true, 'cite' => true], // inserted text
            'kbd'        => [],                          // keyboard input
            'mark'       => [],                          // highlighted text (HTML5)
            'q'          => ['cite' => true],            // inline quotation
            's'          => [],                          // strikethrough
            'small'      => [],                          // fine print
            'span'       => ['class' => true, 'id' => true, 'style' => true],
            'strong'     => [],                          // strong importance (semantic bold)
            'sub'        => [],                          // subscript
            'sup'        => [],                          // superscript
            'time'       => ['datetime' => true, 'class' => true],
            'u'          => [],                          // underline
            'var'        => [],                          // variable in code
            'wbr'        => [],                          // word break opportunity

            // ── Block-level text ─────────────────────────────────────────────
            'blockquote' => ['cite' => true, 'class' => true],
            'br'         => [],
            'dd'         => [],                          // definition description
            'div'        => ['class' => true, 'id' => true, 'style' => true],
            'dl'         => [],                          // definition list
            'dt'         => [],                          // definition term
            'h1'         => ['class' => true, 'id' => true],
            'h2'         => ['class' => true, 'id' => true],
            'h3'         => ['class' => true, 'id' => true],
            'h4'         => ['class' => true, 'id' => true],
            'h5'         => ['class' => true, 'id' => true],
            'h6'         => ['class' => true, 'id' => true],
            'hr'         => ['class' => true],
            'li'         => ['class' => true, 'id' => true, 'value' => true],
            'ol'         => ['class' => true, 'id' => true, 'reversed' => true, 'start' => true, 'type' => true],
            'p'          => ['class' => true, 'id' => true, 'style' => true],
            'pre'        => ['class' => true, 'id' => true],
            'ul'         => ['class' => true, 'id' => true],

            // ── Semantic / structural ────────────────────────────────────────
            'caption'    => ['class' => true],
            'fieldset'   => ['class' => true, 'id' => true],
            'figure'     => ['class' => true, 'id' => true],
            'figcaption' => ['class' => true],
            'footer'     => ['class' => true, 'id' => true],
            'header'     => ['class' => true, 'id' => true],
            'label'      => ['for' => true, 'class' => true],
            'legend'     => [],
            'main'       => ['class' => true, 'id' => true],
            'nav'        => ['class' => true, 'id' => true],
            'section'    => ['class' => true, 'id' => true],

            // ── Media ────────────────────────────────────────────────────────
            // src is a URL attribute; Kses::filter() passes it through UrlSanitizer.
            'img'        => ['alt' => true, 'class' => true, 'height' => true, 'id' => true, 'src' => true, 'width' => true, 'loading' => true],

            // ── Tables ───────────────────────────────────────────────────────
            'col'        => ['span' => true, 'width' => true],
            'colgroup'   => ['span' => true, 'width' => true],
            'table'      => ['class' => true, 'id' => true, 'border' => true, 'cellpadding' => true, 'cellspacing' => true, 'width' => true],
            'tbody'      => ['class' => true],
            'td'         => ['class' => true, 'colspan' => true, 'rowspan' => true, 'width' => true],
            'tfoot'      => ['class' => true],
            'th'         => ['class' => true, 'colspan' => true, 'rowspan' => true, 'scope' => true, 'width' => true],
            'thead'      => ['class' => true],
            'tr'         => ['class' => true],
        ];
    }

    /**
     * Minimal "data" preset — inline emphasis only.
     *
     * Suitable for short descriptive text where only basic inline emphasis
     * is needed: user bios, tooltips, card descriptions, table cell content.
     *
     * Allows links (<a>), basic formatting, and code references.
     * Does NOT allow: headings, images, tables, divs, block-level structure.
     *
     * Equivalent in spirit to the WordPress wp_kses_data() allow-list.
     *
     * @return array<string, array<string, bool>>
     */
    public static function data(): array
    {
        return [
            'a'      => ['href' => true, 'title' => true],  // link (href is URL-validated)
            'abbr'   => ['title' => true],
            'acronym'=> ['title' => true],
            'b'      => [],
            'br'     => [],
            'cite'   => [],
            'code'   => [],
            'del'    => ['datetime' => true],
            'em'     => [],
            'i'      => [],
            'ins'    => ['datetime' => true],
            'q'      => ['cite' => true],
            's'      => [],
            'small'  => [],
            'span'   => [],
            'strong' => [],
            'sub'    => [],
            'sup'    => [],
        ];
    }

    /**
     * "Inline only" preset — zero block-level elements.
     *
     * The most restrictive preset.  Suitable for contexts where you want to
     * allow very basic text decoration but absolutely no structural markup:
     *   • Meta descriptions
     *   • Search result snippets
     *   • Error messages
     *   • Input field labels
     *
     * No links, no images, no divs — just decoration on text that is already
     * there.
     *
     * @return array<string, array<string, bool>>
     */
    public static function inline(): array
    {
        return [
            'abbr'   => ['title' => true],
            'b'      => [],
            'br'     => [],
            'cite'   => [],
            'code'   => [],
            'em'     => [],
            'i'      => [],
            'kbd'    => [],
            's'      => [],
            'small'  => [],
            'span'   => [],
            'strong' => [],
            'sub'    => [],
            'sup'    => [],
            'u'      => [],
        ];
    }
}
