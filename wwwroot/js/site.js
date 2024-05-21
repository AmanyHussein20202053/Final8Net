//function searchInIndex() {

//    let x = document.getElementById("searchIndex").value;

//    if (x == "Java") {
//        window.open("java.html")
//    }
//    if (x == "Web Design") {
//        window.open("WebDesign.html")
//    }
//    if (x == "Data Structure") {
//        window.open("dataStructure.html")
//    }
//    if (x == "C++") {
//        window.open("C++.html")
//    }
//}
// JavaScript to toggle active class on click
document.addEventListener("DOMContentLoaded", function () {
    // Get all title-module elements
    var titleModules = document.querySelectorAll(".title-module");

    // Loop through each title-module element
    titleModules.forEach(function (titleModule) {
        // Get the title element within each title-module
        var title = titleModule.querySelector(".title");
        title.addEventListener("click", function () {
            titleModule.classList.toggle("active");
        });
    });
});

    



