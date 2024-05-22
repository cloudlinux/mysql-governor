/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <string.h>
#include "fifo_stats.h"

void
fifo_stats_free (struct fifo_stats *fifo)
{
	int i = 0;
	while (i < fifo->size)
	{
		free (fifo->ar[i++]);
	}
	free (fifo->ar);
	free (fifo);
}

struct fifo_stats *
fifo_stats_init (int size)
{
	int i = 0;
	struct fifo_stats *fifo = malloc (sizeof (struct fifo_stats));
	if (fifo == NULL)
		return NULL;
	fifo->size = size;
	fifo->ar = calloc (size, sizeof (Stats *));
	if (fifo->ar == NULL)
	{
		free (fifo);
		return NULL;
	}
	while (i < size)
	{
		fifo->ar[i] = calloc (1, sizeof (Stats));
		memset (fifo->ar[i], 0, sizeof (Stats));
		if (fifo->ar[i] == NULL)
		{
			fifo_stats_free (fifo);
			return NULL;
		}
		i++;
	}
	fifo->first = 0;
	return fifo;
}

Stats *
fifo_stats_push (struct fifo_stats * fifo, Stats * x)
{
	Stats *tmp;
	fifo->first = fifo->first - 1;
	if (fifo->first < 0)
	{
		fifo->first = fifo->size - 1;
	}
	tmp = fifo->ar[fifo->first];
	memcpy (fifo->ar[fifo->first], x, sizeof (Stats));
	//fifo->ar[fifo->first] = x;
	return tmp;
}

Stats *
fifo_stats_get (struct fifo_stats * fifo, int i)
{
	int index = fifo->first + i;
	if (index >= fifo->size)
	{
		index -= fifo->size;
	}
	return fifo->ar[index];
}

Stats *
fifo_stats_refresh_last (struct fifo_stats * fifo, Stats * x)
{
	fifo->ar[fifo->first]->cpu += x->cpu;
	fifo->ar[fifo->first]->read += x->read;
	fifo->ar[fifo->first]->write += x->write;
	return fifo->ar[fifo->first];
}

void
fifo_stats_foreach (struct fifo_stats *fifo, void (*fp) (Stats *))
{
	int i = 0;
	while (i < fifo->size)
	{
		fp (fifo_stats_get (fifo, i++));
	}
}

void
fifo_stats_sum (struct fifo_stats *fifo, Stats * sum, int length)
{
	memset (sum, (int) 0, sizeof (Stats));
	int i = 0;
	while (i < fifo->size)
	{
		if (i >= length)
			break;
		Stats *tmp = fifo_stats_get (fifo, i++);
		sum->cpu += tmp->cpu;
		sum->read += tmp->read;
		sum->write += tmp->write;
	}
}

void
fifo_stats_avg (struct fifo_stats *fifo, Stats * sum, int length)
{
	memset (sum, (int) 0, sizeof (Stats));
	int i = 0;
	while (i < fifo->size)
	{
		if (i >= length)
			break;
		Stats *tmp = fifo_stats_get (fifo, i++);
		sum->cpu += tmp->cpu;
		sum->read += tmp->read;
		sum->write += tmp->write;
	}
	if (length > fifo->size)
		length = fifo->size;
	sum->cpu = sum->cpu / length;
	sum->read = sum->read / length;
	sum->write = sum->write / length;
}
