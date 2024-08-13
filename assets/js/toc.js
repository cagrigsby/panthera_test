document.addEventListener("DOMContentLoaded", function () {
  const tocContainer = document.getElementById("toc-container");
  const headers = document.querySelectorAll("h1, h2, h3, h4, h5");

  let tocContent = "";

  headers.forEach(header => {
      const level = parseInt(header.tagName[1]);
      const text = header.textContent;
      const id = header.id;

      if (level === 1) {
          tocContent += `<li><a href="#${id}">${text}</a></li>`;
      } else if (level === 2) {
          tocContent += `<li style="list-style-type: none; margin-left: 20px;">- <a href="#${id}">${text}</a></li>`;
      } else if (level === 3) {
          tocContent += `<li style="list-style-type: none; margin-left: 40px;">-- <a href="#${id}">${text}</a></li>`;
      } else if (level === 4) {
          tocContent += `<li style="list-style-type: none; margin-left: 60px;">--- <a href="#${id}">${text}</a></li>`;
      } else if (level === 5) {
          tocContent += `<li style="list-style-type: none; margin-left: 80px;">---- <a href="#${id}">${text}</a></li>`;
      }
  });

  tocContainer.innerHTML = `<ul style="padding-left: 0;">${tocContent}</ul>`;
});
