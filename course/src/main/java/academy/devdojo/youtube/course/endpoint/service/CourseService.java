package academy.devdojo.youtube.course.endpoint.service;

import academy.devdojo.youtube.core.model.Course;


import academy.devdojo.youtube.core.repository.CourseRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class CourseService {
    @Autowired
    private CourseRepository courseRepository;

    public Iterable<Course> list(Pageable pageable){
        return courseRepository.findAll(pageable);
    }
}
