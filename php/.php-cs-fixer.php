<?php

$finder = PhpCsFixer\Finder::create()
    ->exclude('vendor')
    ->in(__DIR__)
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

$fixers = [
    '@Symfony' => true,
    'align_multiline_comment' => true,
    'array_indentation' => true,
    'array_syntax' => ['syntax' => 'short'],
    'combine_consecutive_issets' => true,
    'combine_consecutive_unsets' => true,
    'compact_nullable_typehint' => true,
    'concat_space' => ['spacing' => 'one'],
    'explicit_indirect_variable' => true,
    'explicit_string_variable' => true,
    'fully_qualified_strict_types' => true,
    'linebreak_after_opening_tag' => true,
    'list_syntax' => ['syntax' => 'short'],
    'method_chaining_indentation' => true,
    'multiline_comment_opening_closing' => true,
    'multiline_whitespace_before_semicolons' => ['strategy' => 'no_multi_line'],
    'native_function_invocation' => ['include' => ['@all']],
    'no_superfluous_phpdoc_tags' => false,
    'not_operator_with_successor_space' => false,
    'ordered_imports' => ['sort_algorithm' => 'alpha'],
    'phpdoc_no_empty_return' => false,
    'phpdoc_order' => true,
    'simple_to_complex_string_variable' => true,
    'single_trait_insert_per_statement' => false,
    'ternary_to_null_coalescing' => true,
    'yoda_style' => false,
];

return (new PhpCsFixer\Config())
    ->setRules($fixers)
    ->setFinder($finder)
    ->setUsingCache(true)
    ->setRiskyAllowed(true)
    ->setIndent('    ')
    ->setLineEnding("\n");