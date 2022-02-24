package edu.cmu.cs.sample;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import lombok.Data;
import lombok.NonNull;

@Data
@Entity
@Table(name = "project")
public class Project {
    @Id
    @Column
    @NonNull
    String projectId;

    @Column
    @NonNull
    String name;

    @ManyToOne
    @JoinColumn(name = "courseId")
    Course course;
}
