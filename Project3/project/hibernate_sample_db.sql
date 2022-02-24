-- MySQL version: 5.7.11+
-- Usage:
-- mysql --username=username -h db_hostname --port db_port --password=user_password --local-infile=1 < hibernate_sample_db.sql

-- create the database
drop database if exists sample_db;
create database sample_db;
use sample_db;

-- create the course table
drop table if exists `course`;
create table `course` (
	`courseId` varchar(22) not null,
	`name` varchar(140) not null,
	primary key (courseId)
);

-- create the project table
drop table if exists `project`;
create table `project` (
	`projectId` varchar(22) not null,
	`name` varchar(140) not null,
	`courseId` varchar(22) not null,
	primary key (projectId),
	foreign key (courseId) references course(courseId)
);
