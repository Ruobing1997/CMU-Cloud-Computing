package edu.cmu.cs.sample;

import edu.cmu.cs.cloud.YelpApp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;

public class Main {
    /**
     * Logger.
     */
    private static final Logger LOGGER = Logger.getRootLogger();

    /**
     * JDBC driver of MySQL Connector/J.
     */
    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    /**
     * Database name.
     */
    private static final String DB_NAME = "sample_db";
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
    private static final String DB_PWD = "dbroot";
    /**
     * The connection (session) with the database.
     */
    private static Connection conn;

    /**
     * This is an example of plain-sql and ORM solutions to insert data into database.
     *
     * @param args
     * Arguments for main method
     */
    public static void main(String[] args) throws SQLException, ClassNotFoundException {
        if (args.length < 1) {
            showUsage();
            System.exit(1);
        }
        switch (args[0]) {
            case "plainSQL":
                plainSQL();
                break;
            case "ORM":
                hibernate();
                break;
            default:
                showUsage();
                System.exit(1);
        }
    }

    /**
     * Show the usage guide for this program.
     */
    private static void showUsage() {
        String jarPath = "target/database_tasks.jar";
        String className = "edu.cmu.cs.sample.Main";
        System.out.println(
                String.format("Usage: java -cp %s %s plainSQL",
                        jarPath, className));
        System.out.println(
                String.format("Usage: java -cp %s %s ORM",
                        jarPath, className));
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
     * Plain-SQL solutions.
     *
     * INSERT INTO `course` (`course_id`, `name`) VALUES
     * ("f20-15319", "Cloud Computing Course");
     * INSERT INTO `project` (`project_id`, `name`, `course_id`) VALUES
     * ("1.1", "Sequential Programming", "f20-15319");
     * INSERT INTO `project` (`project_id`, `name`, `course_id`) VALUES
     * ("1.2", "Parallel Programming", "f20-15319");
     *
     * @throws ClassNotFoundException if JDBC_DRIVER not found.
     * @throws SQLException           with incorrect SQL execution.
     */
    private static void plainSQL() throws SQLException, ClassNotFoundException {
        Course course = new Course("f20-15319", "Cloud Computing Course");
        Project project1 = new Project("1.1", "Sequential Programming");
        project1.setCourse(course);
        Project project2 = new Project("1.2", "Parallel Programming");
        project2.setCourse(course);

        PreparedStatement insertCoursePstmt = null;
        PreparedStatement insertProjectPstmt = null;
        try {
            initializeConnection();

            // map the `Course` class to the `course` table
            insertCoursePstmt = conn.prepareStatement("INSERT INTO `course` (`courseId`, `name`) "
                    + "VALUES (?, ?);");

            // map the fields of the `Course` class to the columns of the `course` table
            insertCoursePstmt.setString(1, course.getCourseId());
            insertCoursePstmt.setString(2, course.getName());

            // map a `Course` object to one row of the `course` table
            insertCoursePstmt.executeUpdate();

            insertProjectPstmt = conn.prepareStatement("INSERT INTO `project` "
                    + "(`projectId`, `name`, `courseId`) "
                    + "VALUES (?, ?, ?);");
            for (Project project : new Project[]{project1, project2}) {
                insertProjectPstmt.setString(1, project.getProjectId());
                insertProjectPstmt.setString(2, project.getName());
                // Association mismatch:
                // Object-oriented languages represent associations using object references
                // where as an RDBMS represents an association as a foreign key.
                Course foreignKeyCourse = project.getCourse();
                insertProjectPstmt.setString(3, foreignKeyCourse.getCourseId());
                insertProjectPstmt.executeUpdate();
            }

            System.out.println("Insert by plain SQL successfully!");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (insertCoursePstmt != null) {
                try {
                    insertCoursePstmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (insertProjectPstmt != null) {
                try {
                    insertProjectPstmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                conn.close();
            }
        }


    }

    /**
     * ORM can abstract plain-SQL queries away from your application.
     *
     * INSERT INTO `course` (`course_id`, `name`) VALUES
     * ("f20-15619", "Cloud Computing Course (Graduate)");
     * INSERT INTO `project` (`project_id`, `name`, `course_id`) VALUES
     * ("phase1", "Twitter Analytics Web Service Phase 1", "f20-15619");
     * INSERT INTO `project` (`project_id`, `name`, `course_id`) VALUES
     * ("phase2", "Twitter Analytics Web Service Phase 2", "f20-15619");
     *
     * @throws ClassNotFoundException if JDBC_DRIVER not found.
     * @throws SQLException           with incorrect SQL execution.
     */
    private static void hibernate() {
        LOGGER.setLevel(Level.OFF);

        Course course = new Course("f20-15619", "Cloud Computing Course (Graduate)");
        Project project1 = new Project("phase1", "Twitter Analytics Web Service Phase 1");
        project1.setCourse(course);
        Project project2 = new Project("phase2", "Twitter Analytics Web Service Phase 2");
        project2.setCourse(course);

        Session session = null;
        SessionFactory sessionFactory = null;
        try {
            sessionFactory = buildSessionFactory();
            session = sessionFactory.getCurrentSession();
            session.beginTransaction();
            session.save(course);
            for (Project project : new Project[]{project1, project2}) {
                session.save(project);
            }
            session.getTransaction().commit();

            System.out.println("Insert by hibernate successfully!");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (session != null && session.isOpen()) {
                session.close();
            }
            if (sessionFactory != null && sessionFactory.isOpen()) {
                sessionFactory.close();
            }
        }
    }

    /**
     * SessionFactory is an immutable thread-safe cache of compiled mappings for
     * a database.
     *
     * @return SessionFactory
     */
    private static SessionFactory buildSessionFactory() {
        try {
            /*
             * Read the database connection configuration from
             * "src/main/resources/hibernate.properties".
             */
            Properties props = new Properties();
            props.load(YelpApp.class.getResourceAsStream(
                    "/hibernate.properties"));
            props.put("hibernate.connection.driver_class", "com.mysql.jdbc.Driver");
            props.put("hibernate.connection.url", URL);
            props.put("hibernate.connection.username", DB_USER);
            props.put("hibernate.connection.password", DB_PWD);

            Configuration configuration = new Configuration();
            configuration.setProperties(props);
            // set the mapping between domain model classes and database tables
            configuration.addAnnotatedClass(Course.class);
            configuration.addAnnotatedClass(Project.class);

            ServiceRegistry serviceRegistry = new StandardServiceRegistryBuilder()
                    .applySettings(configuration.getProperties()).build();
            return configuration.buildSessionFactory(serviceRegistry);
        } catch (Throwable ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }
}

