var order = {};


function plotCharts(container, charts) {
        d3.select(document.getElementById(container))
        .selectAll('div')
        .data(charts)
        .enter()
            .append('div')
                .attr('class', 'vis bor wht rnd shd pad')
                .html(function(d){
                    d.div = this;
                    if(d.type == 'pie') {
                       pieChart(d);
                    } else {
                       barChart(d);
                    }
                    return '<a href="/home/' + encodeURI(d.ID) + '#chart" class="center icn ' + encodeURI(d.key) + '">' + (d.title? ' ' +  d.title : '') + '</a> ';
                    //| <a onclick="downloadElement(\''+encodeURI(d.ID)+'\',this)">download</a>';
                });
    
        d3.select(document.getElementById(container))
        .selectAll('div')
        .data(charts).exit().remove()
}

function showError(a) {
    a.innerHTML = '<div class="tred mid">Error loading data. Try refreshing the page.</div>';
}
function pieChart(a) {
    var w = 710;
    var h = 500;
    var radius = 250;
    
    if('color' in a && 'domain' in a.color && 'range' in a.color && a.color.domain.length > 0) {
        a.color = d3.scale.ordinal()
            .domain(a.color.domain)
            .range(a.color.range);
    } else {
        a.color = d3.scale.category20();
    }

    d3.json(a.href, function(error, data) {
        if(error) {
            showError(a.div);
        }
        
        
        var arc = d3.svg.arc()
            .outerRadius(radius - 10)
            .innerRadius(76);
            
        var pie = d3.layout.pie()
            //.sort(a.sortX)
            .value(function(d) { return d.t; });

        var svgPie = d3.select(a.div).append("svg")
                .attr("id", a.ID)
   // .attr("width", "100%")
    //    .attr("height", "90%")
        .attr("viewBox","0 0 710 500")
            .attr("class", "chart")
            .append("g")
            .attr("transform", "translate(" + w / 2 + "," + h / 2 + ")");

        var total = 0;
        data.forEach(function(d){total+=d.t});
        
        svgPie.append("a").attr("xlink:href", a.list).append("text").text(function(d){return total}).attr("y",0).attr("x",0).attr("class", "sum").attr("text-anchor","middle").attr("alignment-baseline", "central");
    
        var g = svgPie.selectAll(".arc")
            .data(pie(data))
            .enter().append("g")
            .attr("class", "arc");

        g.append("svg:title")
            .text(function(d) { return (d.data._id ? d.data._id : 'null') + ' = ' + d.data.t});
            
        g.append("a")
            .attr("xlink:href", function(d){
                return a.list + "&" + a.key + "=" + (d.data._id ? d.data._id : 'null');
            })
            .append("path")
            .attr("d", arc)
            .attr("class",function(d) { return 'icn ' + d.data._id; } )
            .style("fill", function(d) { return a.color(d.data._id); });

        g.filter(function(d) { return d.endAngle - d.startAngle > .2; })
        .append("a")
            .attr("xlink:href", function(d){
                return a.list + "&" + a.key + "=" + (d.data._id ? d.data._id : 'null');
            })
            .append("text")
            .attr("transform", function(d) {
                arc.innerRadius(radius/2) // Set Outer Coordinate
                return "translate(" + arc.centroid(d) + ")"; 
            })
            .attr("class",function(d) { return 'icn ' + d.data._id; } )
            .attr("dy", "1em")
            .style("text-anchor", "middle")
            .text(function(d) {
                return d.data.t + ' ' + d.data._id;  
            })
    });
};

function barChart (a) {
    'marginLeft' in a ? '' : a.marginLeft = 40;
    'marginRight' in a ? '' : a.marginRight = 20;
    'marginTop' in a ? '' : a.marginTop = 20;
    'marginBottom' in a ? '' : a.marginBottom = 20;
    
    width = 710 - a.marginLeft - a.marginRight,
    height = 500 - a.marginTop - a.marginBottom;

    if(!('x' in a)) {
        a.x = d3.scale.ordinal()
        .rangeRoundBands([0, width], .1);
    }

    if(!('y' in a)) {
        a.y = d3.scale.linear()
        .rangeRound([height, 0]);
    }

    if('color' in a && 'domain' in a.color && 'range' in a.color  && a.color.domain.length > 0) {
        a.color = d3.scale.ordinal()
            .domain(a.color.domain)
            .range(a.color.range);
    } else {
        a.color = d3.scale.category20();
    }

    if(!('xAxis' in a)) {
        a.xAxis = d3.svg.axis()
        .scale(a.x)
        .orient("bottom");
    }

    if(!('yAxis' in a)) {
        a.yAxis = d3.svg.axis()
        .scale(a.y)
        .orient("left")
        .tickFormat(d3.format(".2s"));
    }


    d3.json(a.href, function(error, data) {
                if(error) {
            showError(a.div);
        }
        
         svg = d3.select(a.div).append("svg")
        .attr("id", a.ID)
    //    .attr("height", "90%")
        .attr("viewBox","0 0 710 500")
       // .attr("preserveAspectRatio","xMidYMid meet")
        .attr("class", "chart")
        .append("g")
        .attr("transform", "translate(" + a.marginLeft + "," + a.marginTop + ")");


        var total = 0;
        data.forEach(function(d) {
            var c = d.t;
            total += c;
            var keys = [a.key];
            if(d.items) {
                keys = Object.keys(d.items);
                delete keys.t;
                var y = 0;
                var skey = Object.keys(d.items[0])[0];
                d.items.sort(function(a,b){return a[skey]>b[skey]});
                for (item of d.items) {
                    item.y = y;
                    y = y+item.t;
                }
            }
        });

        a.x.domain(data.map(function(d) {
            return d._id;
        }));
        
        a.y.domain([0, d3.max(data, function(d) {
            return d.t;
        })]);
  
        svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(a.xAxis);

        svg.append("g")
        .attr("class", "y axis")
        .call(a.yAxis);

        svg.append("g")
        .attr("class", "grid")
        .call(a.yAxis
        .tickSize(-width,0,0)
        .tickFormat(""));
  
        svg.append("a").attr("xlink:href", a.list).append("text").text(function(d){return total}).attr("y",50).attr("x",30).attr("class", "sum");

/* total counts above bar charts */
        svg.selectAll("total")
        .data(data)
        .enter().append("a")
            .attr("target", "_blank")
            .attr("xlink:href", (d) => a.list + '&' + a.key[0] + '=' + (d._id?d._id:'null')).append("text")
        .text(function(d) {
            return d.t;
        })
        .attr("y", function(d) {
            return (a.y(d.t) - 2)
        })
        .attr("x", function(d) {
            return a.x(d._id);
        })
        .attr("class", "total")
        ;

/* x axis bars */
        var bars = svg.selectAll(".state")
        .data(data)
        .enter().append("g")
        .attr("class", "g")
        .attr("transform", function(d) {
            return "translate(" + a.x(d._id) + ",0)";
        });

        var ykey;
        if (data[0] && data[0].items && data[0].items[0] && Object.keys(data[0].items[0])[0]) {
            ykey = Object.keys(data[0].items[0])[0];
        }
        /* stacked bar charts */
        bars.selectAll("rect")
        .data(function(d){
            if(Array.isArray(d.items)) {
                var mm = d.items.map(function (x){x._id = d._id; return x});
                return mm;
            } else {
                d.y = 0;
                return [d];
            }
        })
        .enter().append("a")
            .attr("target", "_blank")
            .attr("xlink:href", function(i) {
                return a.list + "&" + a.key[0] + "=" + (i._id ? i._id : 'null')+ (ykey? "&" + ykey + '=' + i[ykey] : '')
            })
        .append("rect")
            .attr("width", a.x.rangeBand())
            .attr("y", function(i) {
              return a.y(i.y + i.t);
            //a.y(i.y);
            })
            .attr("height", function(i) {
                return a.y(i.y)-a.y(i.y + i.t);
            })
        //.attr("class", function(d) { return d.name;})
            .style("fill", function(i) { return a.color(i[ykey]);})
            .append("svg:title")
            .text(function(i) { return i[ykey] + ' = ' + i.t});

        /* bar label */
        bars.selectAll("text").data(function(d) {
            if(Array.isArray(d.items)) {
                var mm = d.items.map(function (x){x._id = d._id; return x});
                return mm;
            } else {
                d.y = 0;
                return [d];
            }
        }).enter().append("a")
            .attr("target", "_blank")
            .attr("xlink:href", function(i){
                return a.list + "&" + a.key[0] + "=" + (i._id?i._id:'null') + (ykey? "&" + ykey + '=' + i[ykey] : '')
        })
        .append("text").text(function(i) {
            if (a.y(i.y)-a.y(i.y + i.t) > 10) {
                return i.t +' ' + (ykey? i[ykey] : '');
            }
            return '';
        })
        .attr("y", function(i) {
            return a.y(i.y)-2;
            //a.y(i.y)+a.y(i.t)+10;
        })
        .attr("x", 2);
    });
};
