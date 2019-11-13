import numpy as np
import matplotlib.pyplot as plt


def time_to_int(_time):
    temp = _time.split(':')
    hh = int(temp[0])
    mm = int(temp[1])
    ss = int(temp[2])
    return hh * 3600 + mm * 60 + ss


def split_ip_port(addr):
    temp = addr.split('.')
    ip = temp[0] + '.' + temp[1] + '.' + temp[2] + '.' + temp[3]
    port = -1
    if len(temp) == 5:
        port = int(temp[4])
    return ip, port


def process_data_to_np(dump_path):
    with open(dump_path) as _input:
        _list = []
        for _line in _input:
            _split = _line.split()
            if _split[1] != 'IP':
                continue
            _time = time_to_int(_split[0].split('.')[0])
            src_ip, src_port = split_ip_port(_split[2])
            dst_ip, dst_port = split_ip_port(_split[4][:len(_split[4]) - 1])
            flags = 'unknow'
            _len = -1
            if _split[5] == 'Flags':
                flags = _split[6][1:len(_split[6]) - 2]
                index = 7
                while _split[index] != 'length':
                    index += 1
                _len = int(_split[index + 1].replace(':', ''))
            _list.append(
                (_time, src_ip, src_port, dst_ip, dst_port, flags, _len))
        _list = np.array(_list)
        np.save(dump_path + '.npy', _list)


def build_dict(data):
    src_dict = dict()
    dst_dict = dict()
    for _tuple in data:
        if _tuple[1] in src_dict:
            src_dict[_tuple[1]].append(_tuple)
        else:
            src_dict[_tuple[1]] = [_tuple]
        if _tuple[3] in dst_dict:
            dst_dict[_tuple[3]].append(_tuple)
        else:
            dst_dict[_tuple[3]] = [_tuple]
    return src_dict, dst_dict


def auto_label(rects, ax):
    for rect in rects:
        height = rect.get_height()
        ax.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords='offset points',
                    ha='center',
                    va='bottom')


def plot_bar(x_label, y_label, title, bar_cnt, bar_label, X, *args):
    width = 0.35
    x = np.arange(0, len(X))
    fig, aix = plt.subplots()
    # ract_dict = dict()
    for i in range(0, bar_cnt):
        # ract_name = 'ract{}'.format(i)
        aix.bar(x + width * ((1 - bar_cnt) / 2 + i),
                args[i],
                width,
                label=bar_label[i])
        # auto_label(rects, aix)

    aix.set_xlabel(x_label)
    aix.set_ylabel(y_label)
    aix.set_title(title)
    aix.set_xticks(x)
    aix.set_xticklabels(X, rotation='vertical')
    aix.legend()

    fig.tight_layout()
    plt.show()


def plot_ip_cnt(data_path):
    data = np.load(data_path)
    src_dict, dst_dict = build_dict(data)
    _set = set()
    for key in src_dict.keys():
        _set.add(key)
    for key in dst_dict.keys():
        _set.add(key)
    X = []
    src_list = []
    dst_list = []
    all_list = []
    for key in _set:
        X.append(key)
        src_cnt = 0
        dst_cnt = 0
        if key in src_dict:
            src_cnt = src_dict[key].__len__()
        if key in dst_dict:
            dst_cnt = dst_dict[key].__len__()
        src_list.append(src_cnt)
        dst_list.append(dst_cnt)
        all_list.append(src_cnt + dst_cnt)

    plot_bar('ip address', 'packet number', 'packet statistic(dos used real ip)', 3,
             ['send', 'recive', 'total'], X, src_list, dst_list, all_list)


if __name__ == '__main__':
    data_path = 'data/scan_dump.npy'
    # process_data_to_np(data_path)
    plot_ip_cnt(data_path)
