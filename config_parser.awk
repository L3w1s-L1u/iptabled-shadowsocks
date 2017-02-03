BEGIN{
    FS="[,:]";
}

$1 ~ pat {
        print $2
}

