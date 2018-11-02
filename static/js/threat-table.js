var threats = $('#threat-datatable').DataTable( {
    "pageLength": 15,
    "lengthMenu": [[15, 25, 50, -1], [15, 25, 50, "All"]],
    'language': {
      "processing": '<div class="loading-dots loading-dots--muted"><span></span><span></span><span></span></div>'
    },

/* The function */

function json2table(json, classes) {
  var cols = Object.keys(json[0]);
  
  var headerRow = '';
  var bodyRows = '';
  
  classes = classes || '';

  function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
  }

  cols.map(function(col) {
    headerRow += '<th>' + capitalizeFirstLetter(col) + '</th>';
  });

  json.map(function(row) {
    bodyRows += '<tr>';

    cols.map(function(colName) {
      bodyRows += '<td>' + row[colName] + '</td>';
    })

    bodyRows += '</tr>';
  });

  return '<table class="' +
         classes +
         '"><thead><tr>' +
         headerRow +
         '</tr></thead><tbody>' +
         bodyRows +
         '</tbody></table>';
}

/* How to use it */

var defaultData = [
  { country: 'China',         population: 1379510000 },
  { country: 'India',         population: 1330780000 },
  { country: 'United States', population:  324788000 },
  { country: 'Indonesia',     population:  260581000 },
  { country: 'Brazil',        population:  206855000 },
];

document.getElementById('threat-datatable').innerHTML = json2table(defaultData, 'table');

/* Live example */

var dom = {
  data: document.getElementById('data'),
  table: document.getElementById('threat-datatable'),
};

dom.data.value = JSON.stringify(defaultData);
dom.data.addEventListener('input', function() {
  dom.table.innerHTML = json2table(JSON.parse(dom.data.value), 'table');
});

// auto refresh the datatable
setInterval( function () {
    threats.ajax.reload();
}, 10000 );
