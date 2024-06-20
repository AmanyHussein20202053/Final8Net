function searchCourses() {
    var searchString = document.getElementById("searchString").value;
    var xhr = new XMLHttpRequest();
    xhr.open("GET", `/Home/Courses?handler=Courses&searchString=${searchString}`, true);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var courses = JSON.parse(xhr.responseText);
            var coursesList = document.getElementById("coursesList");
            coursesList.innerHTML = "";

            if (courses.length > 0) {
                courses.forEach(function (course) {
                    var courseItem = document.createElement("div");
                    courseItem.innerHTML = `<p>${course.title}</p><img src="${course.imageUrl}" alt="${course.title}" /><br/>`;
                    coursesList.appendChild(courseItem);
                });
            } else {
                coursesList.innerHTML = "<p>No courses found.</p>";
            }
        }
    };
    xhr.send();
}
