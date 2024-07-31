document.addEventListener('DOMContentLoaded', function() {
    var sidebar = document.getElementById('sidebar');
    var headers = document.querySelectorAll('#content h1, #content h2, #content h3');
    var ul = document.createElement('ul');
  
    headers.forEach(function(header) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = '#' + header.id;
      a.textContent = header.textContent;
      li.appendChild(a);
      ul.appendChild(li);
    });
  
    sidebar.appendChild(ul);
  });
  