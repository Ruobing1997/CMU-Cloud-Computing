package edu.cmu.scs.cc;

import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.LinkedList;
import java.util.Objects;
import java.util.TreeMap;
import java.util.Locale;
import java.util.Arrays;
import java.util.Map.Entry;

/**
 * <p>Implement a data filter using test-driven development (TDD).</p>
 *
 * <p>A valid line in the pageview files has 4 space-separated fields: <br>
 *
 * <p>{@code domain_code page_title count_views total_response_size} <br>
 *
 * <p>
 * Transform and filter the dataset by the following rules:
 * <ul>
 * <li>Exclude lines that don't have four columns</li>
 * <li>Exclude lines if the the domain code is not exactly "en" or "en.m" (case
 * sensitive)
 * "en" indicates the article is an English desktop page, and "en.m" is for
 * English mobile page</li>
 * <li>The title might be percent-encoded by Wikipedia, use the provided
 * {@link PercentDecoder#decode(String)} method to decode the title for each
 * record
 * e.g. "Special%3ASearch" will be decoded into "Special:Search"</li>
 * <li>Exclude lines that the title starts with any prefix defined in
 * {@link #PREFIX_BLACKLIST} (case insensitive)</li>
 * <li>Exclude lines that the title ends with any suffix defined in
 * {@link #SUFFIX_BLACKLIST} (case insensitive)</li>
 * <li>Exclude lines if the title starts with any lowercase English
 * character</li>
 * <li>Exclude lines if the title is exactly any of the special pages defined in
 * the provided list {@link #SPECIAL_PAGES} (case sensitive)</li>
 * </ul>
 * </p>
 *
 * <p>We provide you with a starter code template, as well as the code of constants,
 * Standard I/O, summing the desktop and mobile site pageviews, and sorting the
 * output.
 *
 * <p>Your task is to implement the methods marked with "To be implemented".</p>
 *
 * <p>Execute the command {@code mvn test} to run the unit tests in
 * DataFilterTest</p>
 */
public final class DataFilter {

    /**
     * Column Name.
     */
    static final int DOMAIN = 0;
    static final int TITLE = 1;
    static final int ACCESS = 2;
    /**
     * Column length.
     */
    private static final int CLEAN_DATA_LENGTH = 4;

    /**
     * Prefix blacklist.
     */
    private static final String[] PREFIX_BLACKLIST = {"media:",
            "special:",
            "talk:",
            "user:",
            "user_talk:",
            "wikipedia:",
            "wikipedia_talk:",
            "file:",
            "file_talk:",
            "mediawiki:",
            "mediawiki_talk:",
            "template:",
            "template_talk:",
            "help:",
            "help_talk:",
            "category:",
            "category_talk:",
            "portal:",
            "portal_talk:",
            "book:",
            "book_talk:",
            "draft:",
            "draft_talk:",
            "education_program:",
            "education_program_talk:",
            "timedtext:",
            "timedtext_talk:",
            "module:",
            "module_talk:",
            "gadget:",
            "gadget_talk:",
            "gadget_definition:",
            "gadget_definition_talk:"};
    /**
     * Suffix blacklist.
     */
    private static final String[] SUFFIX_BLACKLIST = {".png", ".gif",
            ".jpg", ".jpeg",
            ".tiff", ".tif",
            ".xcf", ".mid",
            ".ogg", ".ogv",
            ".svg", ".djvu",
            ".oga", ".flac",
            ".opus", ".wav",
            ".webm", ".ico", ".txt",
            "_(disambiguation)"};

    /**
     * Special pages.
     */
    private static final String[] SPECIAL_PAGES = {
            "Main_Page", "404.php", "-"};


    /**
     * Utility classes should not have a public or default constructor.
     */
    private DataFilter() {

    }

    /**
     * Sort the map in descending numerical order of the values,
     * break ties by the ascending lexicographical order of keys,
     * and return a list of sorted entries.
     *
     * @param records to sort
     * @return sorted entry list.
     */
    static LinkedList<Entry<String, Integer>> sortRecords(
            final TreeMap<String, Integer> records) {
        LinkedList<Entry<String, Integer>> results =
                new LinkedList<>(records.entrySet());
        Collections.sort(results, (e1, e2) -> {
            int cmp = -e1.getValue().compareTo(e2.getValue());
            if (cmp != 0) {
                return cmp;
            } else {
                return e1.getKey().compareTo(e2.getKey());
            }
        });
        return results;
    }

    /**
     * Perform percent-decoding and split the record into columns,
     * separated by single or consecutive whitespaces.
     *
     * <p>We pre-implemented this method for you to help you follow and learn how
     * to perform test-driven development.
     *
     * @param record the pageview record
     * @return columns as a String array
     */
    static String[] getColumns(final String record) {
        return PercentDecoder.decode(record).split("\\s+");
    }

    /**
     * Check if the record passes all the rules.
     *
     * <p>You do not need to modify this method. Instead, you
     * should divide and conquer the complicated filtering task by implementing:
     * {@link #checkDataLength(String[])}
     * {@link #checkDomain(String[])}
     * {@link #checkSpecialPage(String[])}
     * {@link #checkPrefix(String[])}
     * {@link #checkSuffix(String[])}
     * {@link #checkFirstLetter(String[])}
     *
     * @param columns record as columns
     * @return true if the record passes all the rules
     */
    static boolean checkAllRules(final String[] columns) {
        return checkDataLength(columns)
                && checkDomain(columns)
                && checkSpecialPage(columns)
                && checkPrefix(columns)
                && checkSuffix(columns)
                && checkFirstLetter(columns);
    }

    /**
     * Check if column length == 4.
     *
     * @param columns record as columns
     * @return true if length == 4
     */
    static boolean checkDataLength(final String[] columns) {
//        throw new RuntimeException("To be implemented");
        return columns.length == 4;
    }

    /**
     * Check if the domain code is en or en.m (case sensitive).
     *
     * @param columns record as columns
     * @return true if the domain code is en or en.m
     */
    static boolean checkDomain(final String[] columns) {
        return (Objects.equals(columns[0], "en")
                || Objects.equals(columns[0], "en.m"));
    }

    /**
     * Check if the title is any special page, case sensitive.
     *
     * @param columns record as columns
     * @return false if it is a special page
     */
    static boolean checkSpecialPage(final String[] columns) {
        String title = columns[1];
        boolean checker = Arrays.asList(SPECIAL_PAGES).contains(title);
        return !checker;
    }

    /**
     * Check if the title starts with any blacklisted prefix, case insensitive.
     *
     * <p>Any occurrences of {@code %3a} has already been decoded into {@code :}
     * when this method executes (you can assume the text is percent-decoded)
     *
     * @param columns record as columns
     * @return false if the title starts with any blacklisted prefix
     */
    static boolean checkPrefix(final String[] columns) {
        String title = columns[1];
        return !StringUtils.startsWithAny(title.toLowerCase(Locale.ROOT), PREFIX_BLACKLIST);
    }

    /**
     * Check if the title ends with any blacklisted suffix, case insensitive.
     *
     * @param columns record as columns
     * @return false if the title ends with any blacklisted suffix
     */
    static boolean checkSuffix(final String[] columns) {
        String title = columns[1];
        return !StringUtils.endsWithAny(title.toLowerCase(Locale.ROOT), SUFFIX_BLACKLIST);
    }

    /**
     * Check if the first letter of the title is an English lowercase letter.
     *
     * <p>Many other Unicode characters are lowercase too.
     * Only [a-z] should count.
     *
     * <p>Hint: Be careful and read the Javadoc if you want to use
     * {@link Character#isLowerCase(char)}.
     *
     * @param columns record as columns
     * @return false if the title starts with [a-z]
     */
    static boolean checkFirstLetter(final String[] columns) {
        return !columns[1].substring(0,1).matches("[a-z]");
    }
}
