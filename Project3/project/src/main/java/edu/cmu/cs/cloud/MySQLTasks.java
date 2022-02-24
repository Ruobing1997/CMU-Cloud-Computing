package edu.cmu.cs.cloud;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class MySQLTasks {

    /**
     * JDBC driver of MySQL Connector/J.
     */
    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    /**
     * Database name.
     */
    private static final String DB_NAME = "yelp_db";
    /**
     * URL for local MySQL DB.
     *
     * SSL connection must be established by default if explicit option isn't
     * set. For compliance with existing applications not using SSL the
     * verifyServerCertificate property is set to 'false'. You need either to
     * explicitly disable SSL by setting useSSL=false, or set useSSL=true and
     * provide truststore for server certificate verification.
     *
     * Establishing SSL connection without server's identity verification is not
     * recommended. However, we keep it simple and get rid of SSL.
     */
    private static final String URL = "jdbc:mysql://localhost/" + DB_NAME
            + "?useSSL=false";
    /**
     * Username and password.
     */
    private static final String DB_USER = System.getProperty("user.name");
    private static final String DB_PWD = System.getenv("MYSQL_PWD");
    /**
     * The connection (session) with the database.
     */
    private static Connection conn;

    /**
     * Main entry.
     *
     * You are NOT allowed to edit the main entry method.
     *
     * @param args The arguments for main method.
     */
    public static void main(final String[] args) {
        if (args.length != 1) {
            showUsage();
            System.exit(1);
        }
        try {
            initializeConnection();
            switch (args[0]) {
                case "demo":
                    demo();
                    break;
                case "q2":
                    q2();
                    break;
                case "q3":
                    q3();
                    break;
                case "q4":
                    q4();
                    break;
                case "q5":
                    q5();
                    break;
                case "q6":
                    q6();
                    break;
                case "q7":
                    q7();
                    break;
                case "q8":
                    YelpApp.main(new String[]{});
                    break;
                default:
                    showUsage();
                    System.exit(1);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Initialize the database connection.
     *
     * @throws ClassNotFoundException if JDBC_DRIVER not found.
     * @throws SQLException           with incorrect SQL execution.
     */
    private static void initializeConnection() throws ClassNotFoundException,
            SQLException {
        Class.forName(JDBC_DRIVER);
        conn = DriverManager.getConnection(URL, DB_USER, DB_PWD);
    }

    /**
     * Clean up and terminate the connection.
     */
    private static void cleanup() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * JDBC usage demo. The following function will print the row count of the
     * "businesses" table.
     * Table must exists before this function is called.
     */
    private static void demo() {
        String sql = "SELECT count(*) AS cnt FROM businesses";
        executeDataManipulationQuery(sql);
    }

    /**
     * Question 2.
     *
     * Fill in a SQL query that prints the user id who posted the review that
     * received the most "cool".
     * If there are multiple answers, print all of them.
     * Do NOT hardcode your answer.
     *
     * Besides the result of the query,
     * {@link edu.cmu.cs.cloud.MySQLTasks#printScannedRows(String)} will use the EXPLAIN
     * statement to show the predicted scanned rows as the prediction of the
     * performance. The template will do this for you and you only need to
     * focus on the sql query.
     *
     * You are only allowed to edit the sql.
     *
     * The generated output by executing q2 will be:
     * <pre>
     * result
     * number_of_scanned_rows
     * </pre>
     */
    private static void q2() {
        dropCustomIndexesOnReviews();
        String sql = "SELECT user_id FROM reviews WHERE cool = (SELECT MAX(cool) FROM reviews);";
        executeDataManipulationQuery(sql);
        printScannedRows(sql);
    }

    /**
     * Question 3.
     *
     * A database index is a data structure that improves the speed of data
     * retrieval.
     * Identify the column in the reviews table that will improve the
     * performance of the query in question 2, and create a single-column
     * index.
     *
     * A custom index name is needed.
     * The index should be a single-column index instead of a composite index.
     */
    private static void q3() {
        String sql = "CREATE INDEX reviews_index ON reviews (cool);";
        executeDataDefinitionQuery(sql);
        printIndexColumnNames("reviews");
    }

    /**
     * This method is used in {@link edu.cmu.cs.cloud.MySQLTasks#q2()}.
     *
     * KEY and INDEX are synonyms in MySQL.
     * MySQL will build indexes on the primary keys and foreign keys.
     *
     * In the `reviews` table, `create_yelp_database.sql` will create 3
     * indexes:
     * primary key (review_id)
     * foreign key (business_id)
     * foreign key (user_id)
     *
     * This method will drop any other custom index created by you to reset
     * the state of the `reviews` table.
     */
    private static void dropCustomIndexesOnReviews() {
        for (String indexName : getIndexNames("reviews")) {
            executeDataDefinitionQuery(String.format("DROP INDEX %s ON reviews", indexName));
        }
    }

    /**
     * Question 4.
     *
     * Fill in a SQL query that prints the user id who posted the review that
     * received the most "cool".
     * If there are multiple answers, print all of them.
     * Do NOT hardcode your answer.
     *
     * Besides the result of the query,
     * {@link edu.cmu.cs.cloud.MySQLTasks#printScannedRows(String)} will use the EXPLAIN
     * statement to show the predicted scanned rows as the prediction of the
     * performance. The template will do this for you and you only need to
     * focus on the sql query.
     *
     * If you have created a proper index in q3, the number of scanned rows
     * will be much smaller than the prediction in q2.
     *
     * You are only allowed to edit the sql.
     *
     * The generated output by executing q4 will be:
     * <pre>
     * result
     * number_of_scanned_rows
     * </pre>
     */
    private static void q4() {
        String sql = "SELECT user_id FROM reviews WHERE cool = (SELECT MAX(cool) FROM reviews);";
        executeDataManipulationQuery(sql);
        printScannedRows(sql);
    }

    /**
     * Question 5.
     *
     * Which South Side business has "Coast" in its name and has not been
     * checked-in to yet?
     * The output should be the name of the business.
     *
     * Note:
     * The `neighborhood` should be "South Side".
     * The `name` of the business should contain "Coast" as a substring (case
     * sensitive).
     * Use `business_id` as the unique identifier of the business to
     * filter businesses without checkins.
     *
     * If there are multiple answers, print all of them. Do NOT hardcode your
     * answer.
     *
     * You are only allowed to edit the sql.
     */
    private static void q5() {
        String sql = "SELECT name FROM businesses " +
                "LEFT JOIN checkins ON checkins.business_id = businesses.business_id " +
                "WHERE " +
                "neighborhood = 'South Side' AND binary name LIKE '%Coast%' AND checkins.business_id IS NULL;";
        executeDataManipulationQuery(sql);
    }

    /**
     * Question 6.
     *
     * Find the user who posted the coolest review and at least a tip
     * The output should be the id of the user.
     * Note:
     * There is a `cool` column in the review table.
     * If there are multiple answers, print all of them. Do NOT hardcode your
     * answer.
     *
     * You are only allowed to edit the sql.
     */
    private static void q6() {
        String sql = "SELECT r.user_id FROM reviews r " +
                "INNER JOIN tips t ON t.user_id = r.user_id " +
                "ORDER BY r.cool desc LIMIT 1;";
        executeDataManipulationQuery(sql);
    }

    /**
     * Question 7.
     *
     * Find the top 3 cities with the highest average business rating(stars).
     * Break ties by the name of city (in ascending lexicographical order).
     *
     * You are only allowed to edit the sql.
     */
    private static void q7() {
        String sql = "SELECT city, avg(stars) as avg_rating " +
                "FROM businesses " +
                "GROUP BY city " +
                "ORDER BY avg_rating DESC, city ASC " +
                "limit 3;";
        executeDataManipulationQuery(sql);
    }

    /*
     * The methods below are the helper methods.
     * You are NOT allowed to edit any help method, but feel free to read and
     * learn from them.
     */

    /**
     * Show the usage guide for this program.
     */
    private static void showUsage() {
        String jarPath = "target/database_tasks.jar";
        String className = "edu.cmu.cs.cloud.MySQLTasks";
        System.out.println(
                String.format("Usage: java -cp %s %s <question>",
                        jarPath, className));
        System.out.println(
                String.format("Usage: java -cp %s %s demo",
                        jarPath, className));
    }

    /**
     * Get the total number of scanned rows on a query as the EXPLAIN
     * statement predicts.
     *
     * If the value is SQL NULL in the "rows" column,
     * {@link ResultSet#getString(String)} will return null.
     *
     * @param sql to predict the rows to scan.
     */
    private static void printScannedRows(final String sql) {
        String query = "EXPLAIN " + sql;
        Statement stmt = null;
        int rows = 0;
        try {
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                String count = rs.getString("rows");
                rows += count == null ? 0 : Integer.valueOf(count);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
        System.out.println(rows);
    }

    /**
     * Print the column name of the custom index(es) given the table name.
     *
     * The primary key and foreign key (on business_id) created by
     * create_yelp_database.sql will be excluded.
     */
    private static void printIndexColumnNames(String tableName) {
        for (String columnName : getIndexColumnNames(tableName)) {
            System.out.println(columnName);
        }
    }

    /**
     * Get the column name of the custom index(es) given the table name.
     *
     * The primary key and foreign key (on business_id) created by
     * create_yelp_database.sql will be excluded.
     */
    private static List<String> getIndexNames(String tableName) {
        return new LinkedList<>(getIndexes(tableName).keySet());
    }

    /**
     * Get the index name of the custom index(es) given the table name.
     *
     * The primary key and foreign key (on business_id) created by
     * create_yelp_database.sql will be excluded.
     */
    private static List<String> getIndexColumnNames(String tableName) {
        return new LinkedList<>(getIndexes(tableName).values());
    }

    /**
     * Get the custom index(es) given the table name.
     *
     * The primary key and foreign key (on business_id) created by
     * create_yelp_database.sql will be excluded.
     *
     * @return indexes with K: INDEX_NAME, V: COLUMN_NAME
     */
    private static Map<String, String> getIndexes(String tableName) {
        String query =
                String.format("SELECT INDEX_NAME, COLUMN_NAME FROM "
                        + "INFORMATION_SCHEMA.STATISTICS "
                        + "WHERE table_schema = '%s' AND table_name = "
                        + "'%s'", DB_NAME, tableName);
        Statement stmt = null;
        Map<String, String> indexes = new HashMap<>();
        try {
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                String indexName = rs.getString("INDEX_NAME");
                String columnName = rs.getString("COLUMN_NAME");
                if (!indexName.equals("PRIMARY")
                        && !indexName.equals("user_id")
                        && !indexName.equals("business_id")) {
                    indexes.put(indexName, columnName);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
        return indexes;
    }

    /**
     * Execute a SQL Query with DML, iterate the {@link ResultSet} and print
     * the values in the first column.
     *
     * DML is abbreviation of Data Manipulation Language, which is used to
     * retrieve, store, modify, delete, insert and update data in database.
     * e.g.
     * {@code SELECT, UPDATE, INSERT}
     *
     * We expect a single query for each question, not more.
     * Nested query is allowed, but not multiple queries.
     * Retrieves the value of the first column in all the rows.
     *
     * You are not allowed to edit this method.
     *
     * @param sql the sql command to execute
     */
    private static void executeDataManipulationQuery(final String sql) {
        // retain the first query
        String query = sql.split(";")[0];
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Execute a SQL Query with DDL.
     *
     * DDL is abbreviation of Data Definition Language, which is used to
     * create and modify the structure of database objects in database.
     * e.g.
     * {@code CREATE, ALTER, DROP}
     *
     * We expect a single query for each question, not more.
     * Nested query is allowed, but not multiple queries.
     * Retrieves the value of the first column in all the rows.
     *
     * You are not allowed to edit this method.
     *
     * @param sql the sql command to execute
     */
    private static void executeDataDefinitionQuery(final String sql) {
        // retain the first query
        String query = sql.split(";")[0];
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            int rs = stmt.executeUpdate(query);
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
